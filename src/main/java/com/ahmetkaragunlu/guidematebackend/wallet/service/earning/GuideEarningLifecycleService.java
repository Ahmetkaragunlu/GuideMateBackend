package com.ahmetkaragunlu.guidematebackend.wallet.service.earning;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class GuideEarningLifecycleService {

    private static final int BASIS_POINT_DIVISOR = 10_000;

    private final GuideEarningRepository earningRepository;
    private final WalletAccountService walletAccountService;
    private final PaymentProperties paymentProperties;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

    @Transactional
    public GuideEarning createPending(Reservation reservation) {
        return earningRepository.findByReservation_Id(reservation.getId())
                .orElseGet(() -> {
                    long grossMinor = reservation.getTotalPriceMinor();
                    long feeMinor = BigInteger.valueOf(grossMinor)
                            .multiply(BigInteger.valueOf(paymentProperties.platformCommissionBasisPoints()))
                            .divide(BigInteger.valueOf(BASIS_POINT_DIVISOR))
                            .longValueExact();
                    return earningRepository.save(new GuideEarning(
                            reservation,
                            grossMinor,
                            feeMinor,
                            grossMinor - feeMinor,
                            reservation.getCurrencyCode(),
                            reservation.getSession().endsAt()
                    ));
                });
    }

    @Transactional
    public void makeAvailable(UUID reservationId) {
        GuideEarning earning = earningRepository.findByReservationIdForUpdate(reservationId).orElse(null);
        makeAvailable(earning);
    }

    @Transactional
    public void makeAvailableById(UUID earningId) {
        GuideEarning earning = earningRepository.findByIdForUpdate(earningId).orElse(null);
        makeAvailable(earning);
    }

    private void makeAvailable(GuideEarning earning) {
        if (earning == null
                || earning.getStatus() != GuideEarningStatus.PENDING
                || earning.getAvailableAt().isAfter(clock.instant())) {
            return;
        }
        User guide = earning.getReservation().getSession().getTour().getGuide();
        Wallet wallet = walletAccountService.getOrCreateForUpdate(guide);
        earning.makeAvailable();
        walletAccountService.credit(
                wallet,
                new WalletEntryCommand(
                        earning.getNetMinor(),
                        LedgerEntryType.GUIDE_EARNING,
                        "GUIDE_EARNING",
                        earning.getId(),
                        "earning-credit:" + earning.getId(),
                        clock.instant()
                )
        );
        notificationPublisher.publish(new NotificationCommand(
                guide.getId(),
                NotificationType.EARNING_AVAILABLE,
                null,
                Map.of(
                        "earningId", earning.getId().toString(),
                        "reservationId", earning.getReservation().getId().toString(),
                        "tourId", earning.getReservation().getSession().getTour().getId().toString(),
                        "amountMinor", earning.getNetMinor(),
                        "currencyCode", earning.getCurrencyCode()
                ),
                "earning:" + earning.getId()
        ));
    }

    @Transactional
    public void reverse(UUID reservationId) {
        GuideEarning earning = earningRepository.findByReservationIdForUpdate(reservationId).orElse(null);
        if (earning == null || earning.getStatus() == GuideEarningStatus.REVERSED) {
            return;
        }
        GuideEarningStatus previousStatus = earning.getStatus();
        Instant now = clock.instant();
        earning.reverse(now);
        if (previousStatus == GuideEarningStatus.AVAILABLE) {
            User guide = earning.getReservation().getSession().getTour().getGuide();
            Wallet wallet = walletAccountService.getOrCreateForUpdate(guide);
            walletAccountService.recordMandatoryDebit(
                    wallet,
                    new WalletEntryCommand(
                            earning.getNetMinor(),
                            LedgerEntryType.EARNING_REVERSAL,
                            "GUIDE_EARNING",
                            earning.getId(),
                            "earning-reversal:" + earning.getId(),
                            now
                    )
            );
        }
    }

}
