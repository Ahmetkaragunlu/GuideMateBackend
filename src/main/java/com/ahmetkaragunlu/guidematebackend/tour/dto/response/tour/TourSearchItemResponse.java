package com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TourSearchItemResponse(
        // Identity and content
        UUID tourId,
        UUID sessionId,
        String title,
        String categoryCode,

        // Location
        String cityName,
        String countryCode,
        String cityPlaceId,

        // Session and pricing
        Instant startsAt,
        String timeZoneId,
        int durationMinutes,
        long priceMinor,
        String currencyCode,
        int availableCapacity,

        // Presentation and ranking
        List<String> languageCodes,
        MediaReferenceResponse cover,
        double averageRating,
        long reviewCount,
        PublicGuideSummaryResponse guide
) {
}
