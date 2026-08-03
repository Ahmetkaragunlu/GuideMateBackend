package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TourDetailResponse(
        UUID tourId,
        long version,
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
        TourApprovalStatus approvalStatus,
        Instant submittedAt,
        Instant publishedAt,
        Instant reviewedAt,
        String rejectionReason,
        double averageRating,
        long reviewCount,
        List<TourSessionResponse> sessions
) {

    public TourDetailResponse {
        languageCodes = List.copyOf(languageCodes);
        sessions = List.copyOf(sessions);
    }
}
