package com.ahmetkaragunlu.guidematebackend.tour.dto.response.guide;

import com.ahmetkaragunlu.guidematebackend.media.dto.response.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSessionStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record GuideTourCardResponse(
        // Identity and versions
        UUID tourId,
        UUID sessionId,
        long tourVersion,
        long sessionVersion,

        // Tour summary
        String title,
        String cityName,
        String countryCode,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        MediaReferenceResponse cover,

        // Session and pricing
        Instant startsAt,
        int durationMinutes,
        long priceMinor,
        String currencyCode,
        int bookedCount,
        int capacity,

        // Performance and earnings
        double averageRating,
        long reviewCount,
        Long netEarningsMinor,

        // Lifecycle
        TourApprovalStatus approvalStatus,
        TourSessionStatus sessionStatus,
        String rejectionReason,
        boolean canArchive
) {
}
