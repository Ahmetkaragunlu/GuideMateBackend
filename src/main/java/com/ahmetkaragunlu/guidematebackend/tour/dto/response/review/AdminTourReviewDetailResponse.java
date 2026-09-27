package com.ahmetkaragunlu.guidematebackend.tour.dto.response.review;

import com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour.TourDetailResponse;

import java.time.Instant;
import java.util.UUID;

public record AdminTourReviewDetailResponse(
        UUID reviewId,
        AdminTourReviewType type,
        UUID tourId,
        Long guideId,
        String guideDisplayName,
        Instant submittedAt,
        String status,
        TourDetailResponse currentTour,
        TourProposalResponse proposedTour
) {
}
