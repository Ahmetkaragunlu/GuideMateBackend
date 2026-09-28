package com.ahmetkaragunlu.guidematebackend.review.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.response.MediaReferenceResponse;

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
