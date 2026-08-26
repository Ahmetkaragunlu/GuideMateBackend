package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSearchSort;

import java.time.Instant;
import java.util.Set;

public record TourSearchCriteria(
        String query,
        Long guideId,
        String countryCode,
        String cityPlaceId,
        String categoryCode,
        Set<String> languageCodes,
        Double minRating,
        Long minPriceMinor,
        Long maxPriceMinor,
        int page,
        int size,
        TourSearchSort sort,
        Instant now
) {
}
