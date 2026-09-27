package com.ahmetkaragunlu.guidematebackend.tour.dto.response.review;

import com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour.TourDetailResponse;

import java.util.UUID;

public record TourReviewSubmissionResponse(
        UUID reviewId,
        AdminTourReviewType reviewType,
        String reviewStatus,
        TourDetailResponse tour
) {
}
