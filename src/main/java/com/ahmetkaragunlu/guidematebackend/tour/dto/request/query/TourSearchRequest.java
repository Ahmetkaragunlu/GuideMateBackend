package com.ahmetkaragunlu.guidematebackend.tour.dto.request.query;

import com.ahmetkaragunlu.guidematebackend.tour.search.TourSearchSort;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.util.List;

public record TourSearchRequest(
        @Size(max = 100, message = "{validation.tourSearch.query.size}") String q,
        String countryCode,
        @Size(max = 255, message = "{validation.tour.cityPlaceId.size}") String cityPlaceId,
        String categoryCode,
        List<String> languageCodes,
        @DecimalMin(value = "0.0", message = "{validation.tourSearch.minRating.min}")
        @DecimalMax(value = "5.0", message = "{validation.tourSearch.minRating.max}")
        Double minRating,
        @PositiveOrZero(message = "{validation.tourSearch.minPrice.positiveOrZero}") Long minPriceMinor,
        @PositiveOrZero(message = "{validation.tourSearch.maxPrice.positiveOrZero}") Long maxPriceMinor,
        @Min(value = 0, message = "{validation.tourSearch.page.min}") Integer page,
        @Min(value = 1, message = "{validation.tourSearch.size.min}")
        @Max(value = 50, message = "{validation.tourSearch.size.max}")
        Integer size,
        TourSearchSort sort
) {

    public TourSearchRequest {
        page = page == null ? 0 : page;
        size = size == null ? 20 : size;
        sort = sort == null ? TourSearchSort.STARTS_AT_ASC : sort;
    }
}
