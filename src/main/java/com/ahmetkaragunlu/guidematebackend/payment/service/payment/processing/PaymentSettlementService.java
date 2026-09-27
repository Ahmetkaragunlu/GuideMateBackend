package com.ahmetkaragunlu.guidematebackend.payment.service.payment.processing;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.service.refund.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.service.earning.GuideEarningLifecycleService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class PaymentSettlementService {

    private final ReservationFinalizationService reservationFinalizationService;
    private final PaymentRefundService refundService;
    private final WalletAccountService walletAccountService;
    private final GuideEarningLifecycleService guideEarningService;
    private final Clock clock;

    void settleSuccessful(Payment payment, PaymentStatus previousStatus) {
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
        if (previousStatus == PaymentStatus.CANCELLED) {
            reservationFinalizationService.expire(reservation.getId());
            refundService.requestFullRefund(
                    payment.getId(),
                    payment.getUser(),
                    "late-payment:" + payment.getId()
            );
            return;
        }
        ReservationFinalizationResult finalization =
                reservationFinalizationService.finalizeAfterPaymentVerification(reservation.getId());
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

    void expireReservationAfterFailure(Payment payment) {
        if (payment.getReservation() != null) {
            reservationFinalizationService.expire(payment.getReservation().getId());
        }
    }

    private void creditTopUp(Payment payment) {
        Instant now = clock.instant();
        Wallet wallet = walletAccountService.getOrCreateForUpdate(payment.getUser());
        walletAccountService.credit(
                wallet,
                new WalletEntryCommand(
                        payment.getAmountMinor(),
                        LedgerEntryType.TOP_UP,
                        "PAYMENT",
                        payment.getId(),
                        "top-up:" + payment.getId(),
                        now
                )
        );
    }
}
