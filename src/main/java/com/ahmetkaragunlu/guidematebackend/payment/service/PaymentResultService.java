package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentEvent;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.VerifiedPaymentResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentEventRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentResultService {

    private final PaymentRepository paymentRepository;
    private final PaymentEventRepository paymentEventRepository;
    private final ReservationBookingService reservationBookingService;
    private final PaymentRefundService refundService;
    private final WalletAccountService walletAccountService;
    private final GuideEarningService guideEarningService;
    private final ProviderFailureCodeMapper failureCodeMapper;
    private final SensitiveDataCipher dataCipher;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

    @Transactional
    public Payment apply(
            UUID paymentId,
            VerifiedPaymentResult providerResult,
            ProviderVerifiedEvent providerEvent
    ) {
        Payment snapshot = paymentRepository.findById(paymentId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        if (snapshot.getReservation() != null) {
            reservationBookingService.lockSessionForReservation(snapshot.getReservation().getId());
        }
        Payment payment = paymentRepository.findByIdForUpdate(paymentId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        validateProviderResult(payment, providerResult);
        if (paymentEventRepository.existsByProviderEventId(providerEvent.providerEventId())) {
            return payment;
        }

        PaymentStatus previousStatus = payment.getStatus();
        if (!providerResult.successful()) {
            applyFailure(payment, providerResult.providerFailureCode());
            if (payment.getStatus() != previousStatus) {
                publishPaymentResult(payment, NotificationType.PAYMENT_FAILED);
            }
            saveEvent(payment, providerResult, providerEvent);
            return payment;
        }
        requireSuccessfulProviderReferences(providerResult);
        if (payment.getStatus() != PaymentStatus.SUCCEEDED) {
            payment.succeed(
                    providerResult.providerPaymentId(),
                    providerResult.providerTransactionId(),
                    clock.instant()
            );
            applySuccessfulPayment(payment, previousStatus);
            publishPaymentResult(payment, NotificationType.PAYMENT_SUCCEEDED);
        }
        saveEvent(payment, providerResult, providerEvent);
        return payment;
    }

    private void applySuccessfulPayment(Payment payment, PaymentStatus previousStatus) {
        boolean mustRefund = previousStatus == PaymentStatus.CANCELLED
                || previousStatus == PaymentStatus.TIMEOUT;
        if (payment.getPurpose() == PaymentPurpose.WALLET_TOP_UP) {
            if (mustRefund) {
                refundService.requestFullRefund(
                        payment.getId(),
                        payment.getUser(),
                        "cancelled-top-up:" + payment.getId()
                );
                return;
            }
            creditTopUp(payment);
            return;
        }

        Reservation reservation = payment.getReservation();
        if (mustRefund) {
            reservationBookingService.expire(reservation.getId());
            refundService.requestFullRefund(
                    payment.getId(),
                    payment.getUser(),
                    "late-payment:" + payment.getId()
            );
            return;
        }
        ReservationFinalizationResult finalization =
                reservationBookingService.finalizeAfterPaymentVerification(reservation.getId());
        if (finalization.refundRequired()) {
            refundService.requestFullRefund(
                    payment.getId(),
                    payment.getUser(),
                    "late-payment:" + payment.getId()
            );
            return;
        }
        guideEarningService.createPending(finalization.reservation());
    }

    private void creditTopUp(Payment payment) {
        Instant now = clock.instant();
        Wallet wallet = walletAccountService.getOrCreateForUpdate(payment.getUser());
        walletAccountService.credit(
                wallet,
                payment.getAmountMinor(),
                LedgerEntryType.TOP_UP,
                "PAYMENT",
                payment.getId(),
                "top-up:" + payment.getId(),
                now
        );
    }

    private void applyFailure(Payment payment, String providerFailureCode) {
        if (payment.getStatus() != PaymentStatus.CANCELLED
                && payment.getStatus() != PaymentStatus.TIMEOUT
                && payment.getStatus() != PaymentStatus.FAILED) {
            payment.fail(failureCodeMapper.toStableCode(providerFailureCode));
        }
        if (payment.getReservation() != null) {
            reservationBookingService.expire(payment.getReservation().getId());
        }
    }

    private void validateProviderResult(Payment payment, VerifiedPaymentResult result) {
        String storedToken;
        try {
            storedToken = dataCipher.decrypt(payment.getProviderTokenEncrypted());
        } catch (RuntimeException exception) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
        boolean tokenMatches = constantTimeEquals(storedToken, result.token());
        boolean intentMatches = tokenMatches
                && java.util.Objects.equals(payment.getProviderConversationId(), result.conversationId());
        if (result.successful()) {
            intentMatches = intentMatches
                    && payment.getAmountMinor() == result.amountMinor()
                    && payment.getCurrencyCode().equals(result.currencyCode());
        }
        if (!intentMatches) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
    }

    private void requireSuccessfulProviderReferences(VerifiedPaymentResult result) {
        if (isBlank(result.providerPaymentId()) || isBlank(result.providerTransactionId())) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
    }

    private void saveEvent(
            Payment payment,
            VerifiedPaymentResult result,
            ProviderVerifiedEvent event
    ) {
        paymentEventRepository.save(new PaymentEvent(
                payment,
                event.eventType(),
                event.providerEventId(),
                event.payloadHash(),
                result.providerStatus(),
                clock.instant()
        ));
    }

    private boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return MessageDigest.isEqual(
                left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8)
        );
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void publishPaymentResult(Payment payment, NotificationType type) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("paymentId", payment.getId().toString());
        payload.put("purpose", payment.getPurpose().name());
        payload.put("amountMinor", payment.getAmountMinor());
        payload.put("currencyCode", payment.getCurrencyCode());
        if (payment.getReservation() != null) {
            payload.put("reservationId", payment.getReservation().getId().toString());
            payload.put("tourId", payment.getReservation().getSession().getTour().getId().toString());
        }
        notificationPublisher.publish(new NotificationCommand(
                payment.getUser().getId(),
                type,
                null,
                payload
        ));
    }
}
