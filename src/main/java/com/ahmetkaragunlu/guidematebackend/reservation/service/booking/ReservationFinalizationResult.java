package com.ahmetkaragunlu.guidematebackend.reservation.service.booking;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;

public record ReservationFinalizationResult(
        Reservation reservation,
        boolean refundRequired
) {
}
