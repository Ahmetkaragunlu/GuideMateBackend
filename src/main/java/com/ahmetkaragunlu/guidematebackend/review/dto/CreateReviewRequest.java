package com.ahmetkaragunlu.guidematebackend.review.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public record CreateReviewRequest(
        @Min(value = 1, message = "{validation.review.rating.min}")
        @Max(value = 5, message = "{validation.review.rating.max}")
        int rating,

        @Size(max = 2000, message = "{validation.review.comment.size}")
        String comment
) {
}
