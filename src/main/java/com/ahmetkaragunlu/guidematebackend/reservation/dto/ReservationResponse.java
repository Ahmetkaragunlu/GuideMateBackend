package com.ahmetkaragunlu.guidematebackend.reservation.dto;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;

import java.time.Instant;
import java.util.UUID;

public record ReservationResponse(
        UUID reservationId,
        UUID sessionId,
        long version,
        int participantCount,
        long unitPriceMinor,
        long totalPriceMinor,
        String currencyCode,
        ReservationStatus status,
        Instant holdExpiresAt,
        ReservationCancellationActor cancellationActor,
        String cancellationReason,
        Instant cancelledAt,
        RefundEligibility cancellationRefundEligibility,
        String cancellationPolicyCode,
        int cancellationPolicyVersion,
        ReservationSnapshotResponse snapshot,
        ReviewResponse review
) {
}
