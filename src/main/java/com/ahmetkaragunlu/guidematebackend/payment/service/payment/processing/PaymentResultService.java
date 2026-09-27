package com.ahmetkaragunlu.guidematebackend.payment.service.payment.processing;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.crypto.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentEvent;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.event.ProviderVerifiedEvent;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.VerifiedPaymentResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentEventRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.ProviderFailureCodeMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentResultService {

    private final PaymentRepository paymentRepository;
    private final PaymentEventRepository paymentEventRepository;
    private final ReservationFinalizationService reservationFinalizationService;
    private final PaymentSettlementService settlementService;
    private final ProviderFailureCodeMapper failureCodeMapper;
    private final SensitiveDataCipher dataCipher;
    private final PaymentNotificationPublisher notificationPublisher;
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
            reservationFinalizationService.lockSessionForReservation(snapshot.getReservation().getId());
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
                notificationPublisher.publish(payment, NotificationType.PAYMENT_FAILED);
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
            settlementService.settleSuccessful(payment, previousStatus);
            notificationPublisher.publish(payment, NotificationType.PAYMENT_SUCCEEDED);
        }
        saveEvent(payment, providerResult, providerEvent);
        return payment;
    }

    private void applyFailure(Payment payment, String providerFailureCode) {
        if (payment.getStatus() != PaymentStatus.CANCELLED
                && payment.getStatus() != PaymentStatus.TIMEOUT
                && payment.getStatus() != PaymentStatus.FAILED) {
            payment.fail(failureCodeMapper.toStableCode(providerFailureCode));
        }
        settlementService.expireReservationAfterFailure(payment);
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
                    && payment.getChargeAmountMinor() != null
                    && payment.getChargeAmountMinor() == result.amountMinor()
                    && payment.getChargeCurrencyCode().equals(result.currencyCode());
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

}
