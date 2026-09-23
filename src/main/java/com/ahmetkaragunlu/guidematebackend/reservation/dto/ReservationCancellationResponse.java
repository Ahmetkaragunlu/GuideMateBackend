package com.ahmetkaragunlu.guidematebackend.reservation.dto;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.RefundStatus;

import java.util.UUID;

public record ReservationCancellationResponse(
        ReservationResponse reservation,
        RefundEligibility refundEligibility,
        UUID refundId,
        RefundStatus refundStatus
) {
}
