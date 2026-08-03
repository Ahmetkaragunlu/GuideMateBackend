package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record GuideTourCardResponse(
        UUID tourId,
        UUID sessionId,
        long tourVersion,
        long sessionVersion,
        String title,
        String cityName,
        String countryCode,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        MediaReferenceResponse cover,
        Instant startsAt,
        int durationMinutes,
        long priceMinor,
        String currencyCode,
        int bookedCount,
        int capacity,
        TourApprovalStatus approvalStatus,
        TourSessionStatus sessionStatus,
        String rejectionReason,
        boolean canArchive
) {
}
