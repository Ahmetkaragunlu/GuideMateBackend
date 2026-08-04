package com.ahmetkaragunlu.guidematebackend.review.dto;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

import java.time.Instant;
import java.util.UUID;

public record TourReviewResponse(
        UUID reviewId,
        String reviewerDisplayName,
        MediaReferenceResponse reviewerAvatar,
        int rating,
        String comment,
        Instant submittedAt
) {
}
