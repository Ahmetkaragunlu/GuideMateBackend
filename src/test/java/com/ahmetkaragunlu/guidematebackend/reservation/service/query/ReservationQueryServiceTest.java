package com.ahmetkaragunlu.guidematebackend.reservation.service.query;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationTripStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.response.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.mapper.ReservationMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.mapper.ReservationResponseAssembler;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.dto.response.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.service.query.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.query.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationQueryServiceTest {

    @Mock private ReservationRepository reservationRepository;
    @Mock private ReservationCapacityService reservationCapacityService;
    @Mock private ReviewQueryService reviewQueryService;
    @Mock private ReservationMapper reservationMapper;
    private ReservationQueryService service;

    @BeforeEach
    void setUp() {
        ReservationResponseAssembler responseAssembler = new ReservationResponseAssembler(
                reservationCapacityService,
                reviewQueryService,
                reservationMapper
        );
        service = new ReservationQueryService(reservationRepository, responseAssembler);
    }

    @Test
    void returnsTripPageWithBatchedReviewAndCapacityProjections() {
        User tourist = org.mockito.Mockito.mock(User.class);
        UUID reservationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        ReviewResponse review = org.mockito.Mockito.mock(ReviewResponse.class);
        ReviewAggregate aggregate = new ReviewAggregate(4.6, 12);
        ReservationResponse expected = org.mockito.Mockito.mock(ReservationResponse.class);
        PageRequest pageRequest = PageRequest.of(0, 20);

        when(tourist.getId()).thenReturn(42L);
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);
        when(reservationRepository.findUpcomingTrips(42L, ReservationStatus.CONFIRMED, pageRequest))
                .thenReturn(new PageImpl<>(List.of(reservation), pageRequest, 1));
        when(reviewQueryService.reviewsByReservationIds(Set.of(reservationId)))
                .thenReturn(Map.of(reservationId, review));
        when(reviewQueryService.tourAggregates(Set.of(tourId)))
                .thenReturn(Map.of(tourId, aggregate));
        when(reservationCapacityService.occupiedCounts(Set.of(sessionId)))
                .thenReturn(Map.of(sessionId, 7));
        when(reservationMapper.toResponse(reservation, review, aggregate, 7)).thenReturn(expected);

        var result = service.getMyTrips(tourist, ReservationTripStatus.UPCOMING, 0, 20);

        assertThat(result.content()).containsExactly(expected);
        verify(reviewQueryService).tourAggregates(Set.of(tourId));
        verify(reservationCapacityService).occupiedCounts(Set.of(sessionId));
        verify(reservationMapper).toResponse(reservation, review, aggregate, 7);
    }
}
