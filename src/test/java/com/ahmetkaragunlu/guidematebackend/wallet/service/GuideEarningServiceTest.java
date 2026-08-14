package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.MonthlyGuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.MonthlyEarningSummary;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.SessionEarningSummary;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideEarningServiceTest {

    @Mock
    private GuideEarningRepository earningRepository;
    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private PaymentProperties paymentProperties;
    @Mock
    private NotificationPublisher notificationPublisher;

    private GuideEarningService service;

    @BeforeEach
    void setUp() {
        service = new GuideEarningService(
                earningRepository,
                walletAccountService,
                paymentProperties,
                notificationPublisher,
                Clock.fixed(Instant.parse("2026-08-14T00:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void sessionNetEarningsIncludePendingAndAvailableButNotReversed() {
        UUID sessionId = UUID.randomUUID();
        SessionEarningSummary summary = org.mockito.Mockito.mock(SessionEarningSummary.class);
        when(summary.getSessionId()).thenReturn(sessionId);
        when(summary.getNetEarningsMinor()).thenReturn(8_500L);
        when(earningRepository.summarizeBySessionIdsAndStatuses(eq(List.of(sessionId)), any()))
                .thenReturn(List.of(summary));

        Map<UUID, Long> earnings = service.sessionNetEarnings(List.of(sessionId));

        assertThat(earnings).containsEntry(sessionId, 8_500L);
        verify(earningRepository).summarizeBySessionIdsAndStatuses(
                List.of(sessionId),
                List.of(GuideEarningStatus.PENDING, GuideEarningStatus.AVAILABLE)
        );
    }

    @Test
    void mapsMonthlyProjectionInRepositoryOrder() {
        MonthlyEarningSummary august = monthlySummary(2026, 8, 12_000L);
        MonthlyEarningSummary july = monthlySummary(2026, 7, 9_000L);
        when(earningRepository.summarizeMonthlyEarnings(
                eq(42L),
                any(Instant.class),
                any(Instant.class),
                eq(GuideEarningStatus.REVERSED)
        )).thenReturn(List.of(august, july));

        List<MonthlyGuideEarningResponse> result = service.getMonthlyEarnings(42L, 2026);

        assertThat(result).containsExactly(
                new MonthlyGuideEarningResponse(2026, 8, 12_000L, "USD"),
                new MonthlyGuideEarningResponse(2026, 7, 9_000L, "USD")
        );
    }

    private MonthlyEarningSummary monthlySummary(int year, int month, long amount) {
        MonthlyEarningSummary summary = org.mockito.Mockito.mock(MonthlyEarningSummary.class);
        when(summary.getYear()).thenReturn(year);
        when(summary.getMonth()).thenReturn(month);
        when(summary.getNetEarningsMinor()).thenReturn(amount);
        when(summary.getCurrencyCode()).thenReturn("USD");
        return summary;
    }
}
