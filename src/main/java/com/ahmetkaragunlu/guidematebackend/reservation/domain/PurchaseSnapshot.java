package com.ahmetkaragunlu.guidematebackend.reservation.domain;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record PurchaseSnapshot(
        // Snapshot metadata
        int snapshotVersion,

        // Tour
        UUID tourId,
        String title,
        String description,
        UUID coverMediaId,

        // Guide
        Long guideId,
        String guideDisplayName,
        UUID guideAvatarMediaId,

        // Location and classification
        String countryCode,
        String cityPlaceId,
        String cityName,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,

        // Session
        UUID sessionId,
        Instant startsAt,
        int durationMinutes,
        String meetingPoint,

        // Purchase amount
        long unitPriceMinor,
        long totalPriceMinor,
        String currencyCode,
        int participantCount,

        // Cancellation policy
        String cancellationPolicyCode,
        int cancellationPolicyVersion
) {

    public PurchaseSnapshot {
        languageCodes = List.copyOf(languageCodes);
    }
}
