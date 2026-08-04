package com.ahmetkaragunlu.guidematebackend.reservation.domain;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record PurchaseSnapshot(
        int snapshotVersion,
        UUID tourId,
        String title,
        String description,
        UUID coverMediaId,
        Long guideId,
        String guideDisplayName,
        UUID guideAvatarMediaId,
        String countryCode,
        String cityPlaceId,
        String cityName,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        UUID sessionId,
        Instant startsAt,
        int durationMinutes,
        String meetingPoint,
        long unitPriceMinor,
        long totalPriceMinor,
        String currencyCode,
        int participantCount,
        String cancellationPolicyCode,
        int cancellationPolicyVersion
) {

    public PurchaseSnapshot {
        languageCodes = List.copyOf(languageCodes);
    }
}
