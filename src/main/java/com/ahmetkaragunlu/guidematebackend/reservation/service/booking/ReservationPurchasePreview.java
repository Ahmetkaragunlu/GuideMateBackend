package com.ahmetkaragunlu.guidematebackend.reservation.service.booking;

import java.util.UUID;

public record ReservationPurchasePreview(
        UUID sessionId,
        int participantCount,
        long totalPriceMinor,
        String currencyCode
) {
}
