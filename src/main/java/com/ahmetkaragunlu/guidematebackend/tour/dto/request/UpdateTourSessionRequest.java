package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record UpdateTourSessionRequest(
        @NotNull(message = "{validation.version.required}")
        @PositiveOrZero(message = "{validation.version.invalid}")
        Long version,

        @NotBlank(message = "{validation.tourSession.meetingPoint.notBlank}")
        @Size(max = 500, message = "{validation.tourSession.meetingPoint.size}")
        String meetingPoint,

        @NotNull(message = "{validation.tourSession.startsAt.notNull}")
        Instant startsAt,

        @Positive(message = "{validation.tourSession.duration.positive}")
        int durationMinutes,

        @Positive(message = "{validation.tourSession.price.positive}")
        long priceMinor,

        @Positive(message = "{validation.tourSession.capacity.positive}")
        int capacity
) {

    public UpdateTourSessionRequest {
        meetingPoint = meetingPoint == null ? null : meetingPoint.trim();
    }
}
