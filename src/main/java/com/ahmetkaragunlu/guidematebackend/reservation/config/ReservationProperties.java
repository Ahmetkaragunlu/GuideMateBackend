package com.ahmetkaragunlu.guidematebackend.reservation.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "reservation")
public record ReservationProperties(
        Duration holdDuration
) {

    public ReservationProperties {
        if (holdDuration == null || holdDuration.isNegative() || holdDuration.isZero()) {
            throw new IllegalArgumentException("reservation.hold-duration must be positive");
        }
    }
}
