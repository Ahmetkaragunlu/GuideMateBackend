package com.ahmetkaragunlu.guidematebackend.review.dto;

import java.time.Instant;
import java.util.UUID;

public record ReviewResponse(
        UUID reviewId,
        int rating,
        String comment,
        Instant submittedAt
) {
}
