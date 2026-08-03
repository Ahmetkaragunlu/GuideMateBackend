package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TourSearchItemResponse(
        UUID tourId,
        UUID sessionId,
        String title,
        String categoryCode,
        String cityName,
        String countryCode,
        String cityPlaceId,
        Instant startsAt,
        String timeZoneId,
        int durationMinutes,
        long priceMinor,
        String currencyCode,
        int availableCapacity,
        List<String> languageCodes,
        MediaReferenceResponse cover,
        double averageRating,
        long reviewCount,
        PublicGuideSummaryResponse guide
) {
}
