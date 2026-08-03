package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

public record TourContentRequest(
        @NotBlank(message = "{validation.tour.title.notBlank}")
        @Size(min = 3, max = 120, message = "{validation.tour.title.size}")
        String title,

        @NotBlank(message = "{validation.tour.description.notBlank}")
        @Size(min = 20, max = 3000, message = "{validation.tour.description.size}")
        String description,

        @NotBlank(message = "{validation.tour.countryCode.notBlank}")
        @Pattern(regexp = "^[A-Za-z]{2}$", message = "{validation.tour.countryCode.invalid}")
        String countryCode,

        @NotBlank(message = "{validation.tour.cityPlaceId.notBlank}")
        @Size(max = 255, message = "{validation.tour.cityPlaceId.size}")
        String cityPlaceId,

        @NotBlank(message = "{validation.tour.cityName.notBlank}")
        @Size(max = 120, message = "{validation.tour.cityName.size}")
        String cityName,

        @NotBlank(message = "{validation.tour.timeZoneId.notBlank}")
        @Size(max = 64, message = "{validation.tour.timeZoneId.size}")
        String timeZoneId,

        @NotBlank(message = "{validation.tour.categoryCode.notBlank}")
        @Size(max = 32, message = "{validation.tour.categoryCode.size}")
        String categoryCode,

        @NotEmpty(message = "{validation.tour.languages.notEmpty}")
        @Size(max = 20, message = "{validation.tour.languages.size}")
        List<@NotBlank @Pattern(
                regexp = "^[A-Za-z]{2,3}$",
                message = "{validation.tour.language.invalid}"
        ) String> languageCodes,

        @NotNull(message = "{validation.tour.coverMediaId.notNull}")
        UUID coverMediaId
) {

    public TourContentRequest {
        title = trim(title);
        description = trim(description);
        countryCode = trim(countryCode);
        cityPlaceId = trim(cityPlaceId);
        cityName = trim(cityName);
        timeZoneId = trim(timeZoneId);
        categoryCode = trim(categoryCode);
        languageCodes = languageCodes == null
                ? null
                : languageCodes.stream().map(TourContentRequest::trim).toList();
    }

    private static String trim(String value) {
        return value == null ? null : value.trim();
    }
}
