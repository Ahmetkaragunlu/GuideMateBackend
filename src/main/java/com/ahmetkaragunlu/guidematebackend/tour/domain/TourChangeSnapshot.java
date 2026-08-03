package com.ahmetkaragunlu.guidematebackend.tour.domain;

import java.util.List;
import java.util.UUID;

public record TourChangeSnapshot(
        String title,
        String description,
        String countryCode,
        String cityPlaceId,
        String cityName,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        UUID coverMediaId
) {

    public TourChangeSnapshot {
        languageCodes = List.copyOf(languageCodes);
    }
}
