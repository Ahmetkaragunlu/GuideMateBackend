package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

public record SubmitTourChangeRequest(
        @NotNull(message = "{validation.version.required}")
        @PositiveOrZero(message = "{validation.version.invalid}")
        Long baseVersion,

        @Valid @NotNull(message = "{validation.tour.content.notNull}")
        TourContentRequest proposedTour
) {
}
