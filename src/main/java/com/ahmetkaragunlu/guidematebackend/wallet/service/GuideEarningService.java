package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.MonthlyGuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.MonthlyEarningSummary;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.SessionEarningSummary;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GuideEarningService {

    private static final int BASIS_POINT_DIVISOR = 10_000;
    private static final List<GuideEarningStatus> EARNED_STATUSES = List.of(
            GuideEarningStatus.PENDING,
            GuideEarningStatus.AVAILABLE
    );

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
                earning.getNetMinor(),
                LedgerEntryType.GUIDE_EARNING,
                "GUIDE_EARNING",
                earning.getId(),
                "earning-credit:" + earning.getId(),
                clock.instant()
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
                )
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
                    earning.getNetMinor(),
                    LedgerEntryType.EARNING_REVERSAL,
                    "GUIDE_EARNING",
                    earning.getId(),
                    "earning-reversal:" + earning.getId(),
                    now
            );
        }
    }

    @Transactional(readOnly = true)
    public long currentMonthNet(Long guideId) {
        LocalDate firstDay = LocalDate.now(clock).withDayOfMonth(1);
        Instant from = firstDay.atStartOfDay().toInstant(ZoneOffset.UTC);
        Instant until = firstDay.plusMonths(1).atStartOfDay().toInstant(ZoneOffset.UTC);
        return sumNet(earningRepository.findGuideEarningsInPeriod(
                guideId,
                from,
                until,
                GuideEarningStatus.REVERSED
        ));
    }

    @Transactional(readOnly = true)
    public Map<UUID, Long> sessionNetEarnings(Collection<UUID> sessionIds) {
        if (sessionIds.isEmpty()) {
            return Map.of();
        }
        return earningRepository.summarizeBySessionIdsAndStatuses(sessionIds, EARNED_STATUSES).stream()
                .collect(Collectors.toMap(
                        SessionEarningSummary::getSessionId,
                        SessionEarningSummary::getNetEarningsMinor
                ));
    }

    @Transactional(readOnly = true)
    public List<MonthlyGuideEarningResponse> getMonthlyEarnings(Long guideId, int year) {
        Instant from = LocalDate.of(year, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);
        Instant until = LocalDate.of(year + 1, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);
        return earningRepository.summarizeMonthlyEarnings(
                        guideId,
                        from,
                        until,
                        GuideEarningStatus.REVERSED
                ).stream()
                .map(this::toMonthlyResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public Page<GuideEarning> getYear(Long guideId, int year, int page, int size) {
        Instant from = LocalDate.of(year, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);
        Instant until = LocalDate.of(year + 1, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);
        return earningRepository.findGuideEarningsPage(
                guideId,
                from,
                until,
                PageRequest.of(page, size)
        );
    }

    private long sumNet(List<GuideEarning> earnings) {
        return earnings.stream().mapToLong(GuideEarning::getNetMinor).sum();
    }

    private MonthlyGuideEarningResponse toMonthlyResponse(MonthlyEarningSummary summary) {
        return new MonthlyGuideEarningResponse(
                summary.getYear(),
                summary.getMonth(),
                summary.getNetEarningsMinor(),
                summary.getCurrencyCode()
        );
    }
}
