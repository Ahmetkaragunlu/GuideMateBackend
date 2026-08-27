package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.GuideTourTab;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideTourCardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideTourQueryServiceTest {

    @Mock
    private TourRepository tourRepository;
    @Mock
    private TourSessionRepository tourSessionRepository;
    @Mock
    private TourMapper tourMapper;
    @Mock
    private ReservationCapacityService capacityService;
    @Mock
    private ReviewQueryService reviewQueryService;
    @Mock
    private TourDetailQueryService tourDetailQueryService;
    @Mock
    private GuideEarningService guideEarningService;
    @Mock
    private Clock clock;

    @InjectMocks
    private GuideTourQueryService service;

    @Test
    void enrichesGuideCardsWithBatchAggregatesAndHidesCancelledSessionEarnings() {
        Instant now = Instant.parse("2026-08-14T12:00:00Z");
        UUID tourId = UUID.randomUUID();
        UUID completedSessionId = UUID.randomUUID();
        UUID cancelledSessionId = UUID.randomUUID();
        User guide = org.mockito.Mockito.mock(User.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        TourSession completed = session(tour, completedSessionId, TourSessionStatus.COMPLETED);
        TourSession cancelled = session(tour, cancelledSessionId, TourSessionStatus.CANCELLED);
        ReviewAggregate reviews = new ReviewAggregate(4.75, 8);
        GuideTourCardResponse completedCard = card(tourId, completedSessionId, TourSessionStatus.COMPLETED, 9_000L);
        GuideTourCardResponse cancelledCard = card(tourId, cancelledSessionId, TourSessionStatus.CANCELLED, null);

        when(guide.getId()).thenReturn(42L);
        when(tour.getId()).thenReturn(tourId);
        when(clock.instant()).thenReturn(now);
        when(tourSessionRepository.findPastGuideSessions(
                eq(42L),
                anyCollection(),
                any(PageRequest.class)
        )).thenReturn(new PageImpl<>(List.of(completed, cancelled), PageRequest.of(0, 20), 2));
        when(capacityService.occupiedCounts(List.of(completedSessionId, cancelledSessionId)))
                .thenReturn(Map.of(completedSessionId, 3, cancelledSessionId, 1));
        when(reviewQueryService.tourAggregates(List.of(tourId))).thenReturn(Map.of(tourId, reviews));
        when(guideEarningService.sessionNetEarnings(List.of(completedSessionId, cancelledSessionId)))
                .thenReturn(Map.of(completedSessionId, 9_000L, cancelledSessionId, 5_000L));
        when(tourMapper.toGuideCard(completed, 3, reviews, 9_000L)).thenReturn(completedCard);
        when(tourMapper.toGuideCard(cancelled, 1, reviews, null)).thenReturn(cancelledCard);

        PageResponse<GuideTourCardResponse> response = service.getGuideTours(
                guide,
                GuideTourTab.PAST,
                0,
                20
        );

        assertThat(response.content()).containsExactly(completedCard, cancelledCard);
        verify(capacityService).occupiedCounts(List.of(completedSessionId, cancelledSessionId));
        verify(reviewQueryService).tourAggregates(List.of(tourId));
        verify(guideEarningService).sessionNetEarnings(List.of(completedSessionId, cancelledSessionId));
    }

    private TourSession session(Tour tour, UUID sessionId, TourSessionStatus status) {
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(session.getStatus()).thenReturn(status);
        return session;
    }

    private GuideTourCardResponse card(
            UUID tourId,
            UUID sessionId,
            TourSessionStatus status,
            Long earnings
    ) {
        return new GuideTourCardResponse(
                tourId,
                sessionId,
                0,
                0,
                "Tour",
                "Istanbul",
                "TR",
                "Europe/Istanbul",
                "culture",
                List.of("en"),
                null,
                Instant.parse("2026-08-10T10:00:00Z"),
                90,
                10_000,
                "USD",
                3,
                10,
                4.75,
                8,
                earnings,
                TourApprovalStatus.APPROVED,
                status,
                null,
                false
        );
    }
}
