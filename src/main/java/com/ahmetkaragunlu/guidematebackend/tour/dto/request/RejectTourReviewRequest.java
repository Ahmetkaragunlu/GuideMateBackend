package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RejectTourReviewRequest(
        @NotBlank(message = "{validation.tourReview.reason.notBlank}")
        @Size(min = 3, max = 1000, message = "{validation.tourReview.reason.size}")
        String reason
) {

    public RejectTourReviewRequest {
        reason = reason == null ? null : reason.trim();
    }
}
