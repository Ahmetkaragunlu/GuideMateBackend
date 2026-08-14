package com.ahmetkaragunlu.guidematebackend.tour.mapper;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideTourCardResponse;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TourMapperTest {

    private final TourMapper mapper = new TourMapper(new MediaUrlFactory("http://localhost:8080"));

    @Test
    void guideCardKeepsTotalCapacityAndMapsAggregates() {
        UUID tourId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID coverId = UUID.randomUUID();
        Tour tour = mock(Tour.class);
        TourSession session = mock(TourSession.class);
        MediaAsset cover = mock(MediaAsset.class);

        when(tour.getId()).thenReturn(tourId);
        when(tour.getTitle()).thenReturn("Historic Istanbul");
        when(tour.getCityName()).thenReturn("Istanbul");
        when(tour.getCountryCode()).thenReturn("TR");
        when(tour.getTimeZoneId()).thenReturn("Europe/Istanbul");
        when(tour.getCategoryCode()).thenReturn("culture");
        when(tour.getLanguageCodes()).thenReturn(Set.of("en"));
        when(tour.getCoverMedia()).thenReturn(cover);
        when(tour.getApprovalStatus()).thenReturn(TourApprovalStatus.APPROVED);
        when(cover.getId()).thenReturn(coverId);
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(session.getStartsAt()).thenReturn(Instant.parse("2026-09-01T10:00:00Z"));
        when(session.getDurationMinutes()).thenReturn(120);
        when(session.getPriceMinor()).thenReturn(20_000L);
        when(session.getCurrencyCode()).thenReturn("USD");
        when(session.getCapacity()).thenReturn(10);
        when(session.getStatus()).thenReturn(TourSessionStatus.COMPLETED);

        GuideTourCardResponse response = mapper.toGuideCard(
                session,
                4,
                new ReviewAggregate(4.5, 12),
                17_000L
        );

        assertThat(response.capacity()).isEqualTo(10);
        assertThat(response.bookedCount()).isEqualTo(4);
        assertThat(response.averageRating()).isEqualTo(4.5);
        assertThat(response.reviewCount()).isEqualTo(12);
        assertThat(response.netEarningsMinor()).isEqualTo(17_000L);
    }
}
