package com.ahmetkaragunlu.guidematebackend.reservation.mapper;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.response.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.dto.response.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.service.query.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.query.ReviewQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class ReservationResponseAssembler {

    private final ReservationCapacityService reservationCapacityService;
    private final ReviewQueryService reviewQueryService;
    private final ReservationMapper reservationMapper;

    public Page<ReservationResponse> toPage(Page<Reservation> reservations) {
        List<Reservation> content = reservations.getContent();
        Map<UUID, ReviewResponse> reviews = reviewsByReservationId(content);
        Map<UUID, ReviewAggregate> reviewAggregates = reviewAggregatesByTourId(content);
        Map<UUID, Integer> bookedCounts = bookedCountsBySessionId(content);
        return reservations.map(reservation -> reservationMapper.toResponse(
                reservation,
                reviews.get(reservation.getId()),
                reviewAggregates.getOrDefault(tourId(reservation), ReviewAggregate.EMPTY),
                bookedCounts.getOrDefault(reservation.getSession().getId(), 0)
        ));
    }

    public ReservationResponse toResponse(Reservation reservation) {
        UUID tourId = tourId(reservation);
        ReviewAggregate reviewAggregate = reviewQueryService
                .tourAggregates(Set.of(tourId))
                .getOrDefault(tourId, ReviewAggregate.EMPTY);
        return reservationMapper.toResponse(
                reservation,
                reviewQueryService.reviewByReservationId(reservation.getId()),
                reviewAggregate,
                reservationCapacityService.occupiedCount(reservation.getSession().getId())
        );
    }

    private Map<UUID, ReviewResponse> reviewsByReservationId(List<Reservation> reservations) {
        Set<UUID> reservationIds = reservations.stream()
                .map(Reservation::getId)
                .collect(Collectors.toSet());
        return reviewQueryService.reviewsByReservationIds(reservationIds);
    }

    private Map<UUID, ReviewAggregate> reviewAggregatesByTourId(List<Reservation> reservations) {
        Set<UUID> tourIds = reservations.stream()
                .map(this::tourId)
                .collect(Collectors.toSet());
        if (tourIds.isEmpty()) {
            return Map.of();
        }
        return reviewQueryService.tourAggregates(tourIds);
    }

    private Map<UUID, Integer> bookedCountsBySessionId(List<Reservation> reservations) {
        Set<UUID> sessionIds = reservations.stream()
                .map(reservation -> reservation.getSession().getId())
                .collect(Collectors.toSet());
        if (sessionIds.isEmpty()) {
            return Map.of();
        }
        return reservationCapacityService.occupiedCounts(sessionIds);
    }

    private UUID tourId(Reservation reservation) {
        return reservation.getSession().getTour().getId();
    }
}
