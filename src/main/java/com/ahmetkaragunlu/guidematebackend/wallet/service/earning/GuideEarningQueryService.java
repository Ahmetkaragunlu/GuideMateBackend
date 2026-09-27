package com.ahmetkaragunlu.guidematebackend.wallet.service.earning;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.response.MonthlyGuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.projection.MonthlyEarningSummary;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.projection.SessionEarningSummary;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
public class GuideEarningQueryService {

    private static final List<GuideEarningStatus> EARNED_STATUSES = List.of(
            GuideEarningStatus.PENDING,
            GuideEarningStatus.AVAILABLE
    );

    private final GuideEarningRepository earningRepository;
    private final Clock clock;

    @Transactional(readOnly = true)
    public long currentMonthNet(Long guideId) {
        LocalDate firstDay = LocalDate.now(clock).withDayOfMonth(1);
        Instant from = firstDay.atStartOfDay().toInstant(ZoneOffset.UTC);
        Instant until = firstDay.plusMonths(1).atStartOfDay().toInstant(ZoneOffset.UTC);
        return earningRepository.findGuideEarningsInPeriod(
                        guideId,
                        from,
                        until,
                        GuideEarningStatus.REVERSED
                ).stream()
                .mapToLong(GuideEarning::getNetMinor)
                .sum();
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
                        GuideEarningStatus.REVERSED,
                        GuideEarningStatus.PENDING
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

    private MonthlyGuideEarningResponse toMonthlyResponse(MonthlyEarningSummary summary) {
        return new MonthlyGuideEarningResponse(
                summary.getYear(),
                summary.getMonth(),
                summary.getNetEarningsMinor(),
                summary.getCurrencyCode(),
                summary.getPendingEarningsMinor()
        );
    }
}
