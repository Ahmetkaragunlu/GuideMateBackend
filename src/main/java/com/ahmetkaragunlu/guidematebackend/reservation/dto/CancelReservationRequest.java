package com.ahmetkaragunlu.guidematebackend.reservation.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

public record CancelReservationRequest(
        @NotNull(message = "{validation.version.required}")
        @PositiveOrZero(message = "{validation.version.invalid}")
        Long version,

        @Size(max = 1000, message = "{validation.reservation.cancellationReason.size}")
        String reason
) {
}
