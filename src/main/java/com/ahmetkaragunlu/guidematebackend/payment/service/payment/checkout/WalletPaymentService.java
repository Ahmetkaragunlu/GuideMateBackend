package com.ahmetkaragunlu.guidematebackend.payment.service.payment.checkout;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.service.earning.GuideEarningLifecycleService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class WalletPaymentService {

    private final PaymentRepository paymentRepository;
    private final UserRepository userRepository;
    private final ReservationBookingService reservationBookingService;
    private final ReservationFinalizationService reservationFinalizationService;
    private final WalletAccountService walletAccountService;
    private final GuideEarningLifecycleService guideEarningService;
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final Clock clock;

    @Transactional
    public Payment purchaseTour(
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
            requireSamePurchase(previous, reservation);
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
                new WalletEntryCommand(
                        payment.getAmountMinor(),
                        LedgerEntryType.TOUR_PURCHASE,
                        "PAYMENT",
                        payment.getId(),
                        "tour-purchase:" + payment.getId(),
                        now
                )
        );
        ReservationFinalizationResult finalization =
                reservationFinalizationService.finalizeAfterPaymentVerification(reservation.getId());
        if (finalization.refundRequired()) {
            throw new BusinessException(ErrorCode.DATA_CONFLICT);
        }
        guideEarningService.createPending(finalization.reservation());
        return payment;
    }

    private void requireSamePurchase(Payment payment, Reservation reservation) {
        if (payment.getMethod() != PaymentMethod.WALLET
                || payment.getAmountMinor() != reservation.getTotalPriceMinor()
                || !Objects.equals(
                payment.getFxQuote() == null ? null : payment.getFxQuote().getId(),
                null
        )
                || !Objects.equals(
                payment.getReservation() == null ? null : payment.getReservation().getId(),
                reservation.getId()
        )) {
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }
    }
}
