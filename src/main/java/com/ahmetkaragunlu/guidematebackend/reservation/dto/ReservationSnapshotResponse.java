package com.ahmetkaragunlu.guidematebackend.reservation.dto;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.PublicGuideSummaryResponse;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ReservationSnapshotResponse(
        UUID tourId,
        PublicGuideSummaryResponse guide,
        String title,
        String description,
        String countryCode,
        String cityPlaceId,
        String cityName,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        MediaReferenceResponse cover,
        Instant startsAt,
        int durationMinutes,
        String meetingPoint,
        long unitPriceMinor
) {

    public ReservationSnapshotResponse {
        languageCodes = List.copyOf(languageCodes);
    }
}
