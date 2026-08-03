package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

public record CreateTourRequest(
        @Valid @NotNull(message = "{validation.tour.content.notNull}")
        TourContentRequest tour,

        @Valid @NotNull(message = "{validation.tour.session.notNull}")
        CreateTourSessionRequest session
) {
}
