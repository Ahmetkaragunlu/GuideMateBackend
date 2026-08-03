package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

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
