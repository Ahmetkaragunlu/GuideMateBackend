package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CancelTourSessionRequest(
        @NotBlank(message = "{validation.tourSession.cancellationReason.notBlank}")
        @Size(min = 3, max = 1000, message = "{validation.tourSession.cancellationReason.size}")
        String reason
) {

    public CancelTourSessionRequest {
        reason = reason == null ? null : reason.trim();
    }
}
