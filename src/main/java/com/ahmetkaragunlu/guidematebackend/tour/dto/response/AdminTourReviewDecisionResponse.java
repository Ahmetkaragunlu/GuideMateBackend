package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import java.time.Instant;
import java.util.UUID;

public record AdminTourReviewDecisionResponse(
        UUID reviewId,
        AdminTourReviewType type,
        String status,
        Instant reviewedAt,
        TourDetailResponse tour
) {
}
