package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideLevel;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.GuideParticipantSummary;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.repository.GuideCompletedSessionCount;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuidePerformanceServiceTest {

    @Mock private TourSessionRepository sessionRepository;
    @Mock private ReservationRepository reservationRepository;
    @Mock private ReviewQueryService reviewQueryService;
    @Mock private GuideLevelPolicy levelPolicy;
    private GuidePerformanceService service;

    @BeforeEach
    void setUp() {
        service = new GuidePerformanceService(
                sessionRepository,
                reservationRepository,
                reviewQueryService,
                levelPolicy
        );
    }

    @Test
    void combinesBatchAggregatesAndDefaultsMissingGuideData() {
        GuideCompletedSessionCount sessions = mock(GuideCompletedSessionCount.class);
        GuideParticipantSummary participants = mock(GuideParticipantSummary.class);
        when(sessions.getGuideId()).thenReturn(1L);
        when(sessions.getCompletedSessionCount()).thenReturn(20L);
        when(participants.getGuideId()).thenReturn(1L);
        when(participants.getParticipantCount()).thenReturn(48L);
        when(sessionRepository.countCompletedSessionsByGuideIds(any(), any())).thenReturn(List.of(sessions));
        when(reservationRepository.sumCompletedParticipantsByGuideIds(any(), any()))
                .thenReturn(List.of(participants));
        when(reviewQueryService.guideAggregates(Set.of(1L, 2L)))
                .thenReturn(Map.of(1L, new ReviewAggregate(4.7, 12)));
        when(levelPolicy.resolve(20, 4.7, 12)).thenReturn(GuideLevel.SUPER);
        when(levelPolicy.resolve(0, 0.0, 0)).thenReturn(GuideLevel.APPROVED);

        var result = service.getAll(Set.of(1L, 2L));

        assertThat(result.get(1L).totalParticipantCount()).isEqualTo(48);
        assertThat(result.get(1L).level()).isEqualTo(GuideLevel.SUPER);
        assertThat(result.get(2L).completedSessionCount()).isZero();
        assertThat(result.get(2L).level()).isEqualTo(GuideLevel.APPROVED);
    }
}
