package com.ahmetkaragunlu.guidematebackend.tour.dto.request;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSearchSort;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.util.List;

public record TourSearchRequest(
        @Size(max = 100) String q,
        String countryCode,
        @Size(max = 255) String cityPlaceId,
        String categoryCode,
        List<String> languageCodes,
        @DecimalMin("0.0") @DecimalMax("5.0") Double minRating,
        @PositiveOrZero Long minPriceMinor,
        @PositiveOrZero Long maxPriceMinor,
        @Min(0) Integer page,
        @Min(1) @Max(50) Integer size,
        TourSearchSort sort
) {

    public TourSearchRequest {
        page = page == null ? 0 : page;
        size = size == null ? 20 : size;
        sort = sort == null ? TourSearchSort.STARTS_AT_ASC : sort;
    }
}
