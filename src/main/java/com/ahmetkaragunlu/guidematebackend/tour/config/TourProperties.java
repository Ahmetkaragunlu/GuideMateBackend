package com.ahmetkaragunlu.guidematebackend.tour.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "tour")
public record TourProperties(@NotBlank String currencyCode) {

    public TourProperties {
        if (currencyCode != null && !"USD".equals(currencyCode)) {
            throw new IllegalArgumentException("tour.currency-code must be USD");
        }
    }
}
