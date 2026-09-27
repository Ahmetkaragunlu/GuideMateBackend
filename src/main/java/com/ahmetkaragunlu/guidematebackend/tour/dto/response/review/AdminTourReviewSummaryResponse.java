package com.ahmetkaragunlu.guidematebackend.tour.dto.response.review;

import java.time.Instant;
import java.util.UUID;

public record AdminTourReviewSummaryResponse(
        UUID reviewId,
        AdminTourReviewType type,
        UUID tourId,
        Long guideId,
        String guideDisplayName,
        String title,
        Instant submittedAt
) {
}
