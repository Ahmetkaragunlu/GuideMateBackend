package com.ahmetkaragunlu.guidematebackend.reservation.dto;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;

public record ReservationCancellationResponse(
        ReservationResponse reservation,
        RefundEligibility refundEligibility
) {
}
