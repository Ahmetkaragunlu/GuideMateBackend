package com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour;

import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourCancellationActor;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSessionStatus;

import java.time.Instant;
import java.util.UUID;

public record TourSessionResponse(
        UUID sessionId,
        UUID tourId,
        long version,
        String meetingPoint,
        Instant startsAt,
        int durationMinutes,
        long priceMinor,
        String currencyCode,
        int capacity,
        int bookedCount,
        int availableCapacity,
        TourSessionStatus status,
        TourCancellationActor cancellationActor,
        String cancellationReason,
        Instant cancelledAt
) {
}
