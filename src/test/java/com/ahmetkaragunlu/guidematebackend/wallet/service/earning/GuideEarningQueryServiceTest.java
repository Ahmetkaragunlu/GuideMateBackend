package com.ahmetkaragunlu.guidematebackend.wallet.service.earning;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.projection.SessionEarningSummary;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideEarningQueryServiceTest {

    @Mock
    private GuideEarningRepository earningRepository;

    @Test
    void sessionNetEarningsIncludePendingAndAvailableButNotReversed() {
        UUID sessionId = UUID.randomUUID();
        SessionEarningSummary summary = mock(SessionEarningSummary.class);
        when(summary.getSessionId()).thenReturn(sessionId);
        when(summary.getNetEarningsMinor()).thenReturn(8_500L);
        when(earningRepository.summarizeBySessionIdsAndStatuses(eq(List.of(sessionId)), any()))
                .thenReturn(List.of(summary));
        GuideEarningQueryService service = new GuideEarningQueryService(
                earningRepository,
                Clock.fixed(Instant.parse("2026-08-14T00:00:00Z"), ZoneOffset.UTC)
        );

        Map<UUID, Long> earnings = service.sessionNetEarnings(List.of(sessionId));

        assertThat(earnings).containsEntry(sessionId, 8_500L);
        verify(earningRepository).summarizeBySessionIdsAndStatuses(
                List.of(sessionId),
                List.of(GuideEarningStatus.PENDING, GuideEarningStatus.AVAILABLE)
        );
    }
}
