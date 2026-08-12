package com.ahmetkaragunlu.guidematebackend.reservation.service;

import java.util.UUID;

public record ReservationPurchasePreview(
        UUID sessionId,
        int participantCount,
        long totalPriceMinor,
        String currencyCode
) {
}
