package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedCheckoutSession;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.List;

@Service
@RequiredArgsConstructor
public class PaymentIntentService {

    private final PaymentRepository paymentRepository;
    private final UserRepository userRepository;
    private final ReservationBookingService reservationBookingService;
    private final WalletAccountService walletAccountService;
    private final GuideEarningService guideEarningService;
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final SensitiveDataCipher dataCipher;
    private final PaymentProperties properties;
    private final Clock clock;

    @Transactional
    public HostedPaymentIntent createHostedTourIntent(
            User tourist,
            UUID sessionId,
            int participantCount,
            String idempotencyKey
    ) {
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
        Reservation reservation = reservationBookingService.createHold(
                tourist,
                sessionId,
                participantCount,
                normalizedKey
        );
        Payment previous = paymentRepository.findByUser_IdAndPurposeAndIdempotencyKey(
                tourist.getId(),
                PaymentPurpose.TOUR_BOOKING,
                normalizedKey
        ).orElse(null);
        if (previous != null) {
            requireSameIntent(previous, PaymentMethod.HOSTED_CARD, reservation, reservation.getTotalPriceMinor());
            return new HostedPaymentIntent(previous, previous.getStatus() == PaymentStatus.PENDING);
        }
        Payment payment = Payment.hosted(
                userRepository.getReferenceById(tourist.getId()),
                PaymentPurpose.TOUR_BOOKING,
                reservation,
                reservation.getTotalPriceMinor(),
                reservation.getCurrencyCode(),
                normalizedKey
        );
        return new HostedPaymentIntent(paymentRepository.saveAndFlush(payment), true);
    }

    @Transactional
    public HostedPaymentIntent createTopUpIntent(User tourist, long amountMinor, String idempotencyKey) {
        requireTourist(tourist);
        requirePositiveAmount(amountMinor);
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
        Payment previous = paymentRepository.findByUser_IdAndPurposeAndIdempotencyKey(
                tourist.getId(),
                PaymentPurpose.WALLET_TOP_UP,
                normalizedKey
        ).orElse(null);
        if (previous != null) {
            requireSameIntent(previous, PaymentMethod.HOSTED_CARD, null, amountMinor);
            return new HostedPaymentIntent(previous, previous.getStatus() == PaymentStatus.PENDING);
        }
        Payment payment = Payment.hosted(
                userRepository.getReferenceById(tourist.getId()),
                PaymentPurpose.WALLET_TOP_UP,
                null,
                amountMinor,
                properties.currencyCode(),
                normalizedKey
        );
        return new HostedPaymentIntent(paymentRepository.saveAndFlush(payment), true);
    }

    @Transactional
    public Payment purchaseTourWithWallet(
            User tourist,
            UUID sessionId,
            int participantCount,
            String idempotencyKey
    ) {
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
        Reservation reservation = reservationBookingService.createHold(
                tourist,
                sessionId,
                participantCount,
                normalizedKey
        );
        Payment previous = paymentRepository.findByUser_IdAndPurposeAndIdempotencyKey(
                tourist.getId(),
                PaymentPurpose.TOUR_BOOKING,
                normalizedKey
        ).orElse(null);
        if (previous != null) {
            requireSameIntent(previous, PaymentMethod.WALLET, reservation, reservation.getTotalPriceMinor());
            return previous;
        }

        Instant now = clock.instant();
        Wallet wallet = walletAccountService.getOrCreateForUpdate(tourist);
        Payment payment = paymentRepository.saveAndFlush(Payment.wallet(
                userRepository.getReferenceById(tourist.getId()),
                reservation,
                reservation.getTotalPriceMinor(),
                reservation.getCurrencyCode(),
                normalizedKey,
                now
        ));
        walletAccountService.debit(
                wallet,
                payment.getAmountMinor(),
                LedgerEntryType.TOUR_PURCHASE,
                "PAYMENT",
                payment.getId(),
                "tour-purchase:" + payment.getId(),
                now
        );
        ReservationFinalizationResult finalization =
                reservationBookingService.finalizeAfterPaymentVerification(reservation.getId());
        if (finalization.refundRequired()) {
            throw new BusinessException(ErrorCode.DATA_CONFLICT);
        }
        guideEarningService.createPending(finalization.reservation());
        return payment;
    }

    @Transactional
    public Payment completeInitialization(UUID paymentId, HostedCheckoutSession session, String conversationId) {
        Payment payment = requireForUpdate(paymentId);
        if (payment.getStatus() == PaymentStatus.REQUIRES_ACTION) {
            return payment;
        }
        if (payment.getStatus() != PaymentStatus.PENDING) {
            return payment;
        }
        payment.markRequiresAction(
                dataCipher.encrypt(session.token()),
                dataCipher.fingerprint(session.token()),
                conversationId,
                session.paymentPageUrl(),
                clock.instant().plus(session.expiresIn())
        );
        return payment;
    }

    @Transactional
    public void failInitialization(UUID paymentId, String providerFailureCode) {
        lockPaymentSession(paymentId);
        Payment payment = requireForUpdate(paymentId);
        if (payment.getStatus() != PaymentStatus.PENDING) {
            return;
        }
        payment.fail(providerFailureCode);
        if (payment.getReservation() != null) {
            reservationBookingService.expire(payment.getReservation().getId());
        }
    }

    @Transactional
    public Payment cancel(User currentUser, UUID paymentId) {
        lockPaymentSession(paymentId);
        Payment payment = paymentRepository.findByIdForUpdate(paymentId)
                .filter(candidate -> candidate.getUser().getId().equals(currentUser.getId()))
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        if (payment.getStatus() == PaymentStatus.CANCELLED) {
            return payment;
        }
        if (payment.getStatus() != PaymentStatus.PENDING
                && payment.getStatus() != PaymentStatus.REQUIRES_ACTION) {
            throw new BusinessException(ErrorCode.PAYMENT_NOT_CANCELLABLE);
        }
        payment.cancel();
        if (payment.getReservation() != null) {
            reservationBookingService.expire(payment.getReservation().getId());
        }
        return payment;
    }

    @Transactional
    public void markVerifying(UUID paymentId) {
        Payment payment = requireForUpdate(paymentId);
        if (payment.getStatus() == PaymentStatus.PENDING
                || payment.getStatus() == PaymentStatus.REQUIRES_ACTION) {
            payment.markVerifying();
        }
    }

    @Transactional
    public void cancelPendingForReservation(UUID reservationId) {
        paymentRepository.findByReservationIdAndStatusesForUpdate(
                        reservationId,
                        List.of(PaymentStatus.PENDING, PaymentStatus.REQUIRES_ACTION)
                )
                .forEach(Payment::cancel);
    }

    private Payment requireForUpdate(UUID paymentId) {
        return paymentRepository.findByIdForUpdate(paymentId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
    }

    private void lockPaymentSession(UUID paymentId) {
        Payment snapshot = paymentRepository.findById(paymentId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        if (snapshot.getReservation() != null) {
            reservationBookingService.lockSessionForReservation(snapshot.getReservation().getId());
        }
    }

    private void requireSameIntent(
            Payment payment,
            PaymentMethod method,
            Reservation reservation,
            long amountMinor
    ) {
        if (payment.getMethod() != method
                || payment.getAmountMinor() != amountMinor
                || !java.util.Objects.equals(
                payment.getReservation() == null ? null : payment.getReservation().getId(),
                reservation == null ? null : reservation.getId()
        )) {
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }
    }

    private void requirePositiveAmount(long amountMinor) {
        if (amountMinor <= 0) {
            throw new BusinessException(ErrorCode.INVALID_AMOUNT);
        }
    }

    private void requireTourist(User user) {
        if (user.getRole() == null || !RoleType.ROLE_TOURIST.name().equals(user.getRole().getName())) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
    }
}
