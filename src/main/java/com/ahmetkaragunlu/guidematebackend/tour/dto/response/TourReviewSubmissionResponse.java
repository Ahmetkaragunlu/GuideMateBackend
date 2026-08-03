package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import java.util.UUID;

public record TourReviewSubmissionResponse(
        UUID reviewId,
        AdminTourReviewType reviewType,
        String reviewStatus,
        TourDetailResponse tour
) {
}
