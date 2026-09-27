package com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.TourApprovalStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TourDetailResponse(
        // Identity
        UUID tourId,
        long version,

        // Guide
        PublicGuideSummaryResponse guide,

        // Content, location and classification
        String title,
        String description,
        String countryCode,
        String cityPlaceId,
        String cityName,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        MediaReferenceResponse cover,

        // Review lifecycle
        TourApprovalStatus approvalStatus,
        Instant submittedAt,
        Instant publishedAt,
        Instant reviewedAt,
        String rejectionReason,

        // Rating
        double averageRating,
        long reviewCount,

        // Sessions
        List<TourSessionResponse> sessions
) {

    public TourDetailResponse {
        languageCodes = List.copyOf(languageCodes);
        sessions = List.copyOf(sessions);
    }
}
