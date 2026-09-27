package com.ahmetkaragunlu.guidematebackend.tour.dto.response.review;

import com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour.TourDetailResponse;

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
