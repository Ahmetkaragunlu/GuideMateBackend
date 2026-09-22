package com.ahmetkaragunlu.guidematebackend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "google")
public record GoogleAuthProperties(
        String clientId,
        Duration connectTimeout,
        Duration readTimeout
) {

    public GoogleAuthProperties {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("google.client-id is required");
        }
        requirePositive(connectTimeout, "google.connect-timeout");
        requirePositive(readTimeout, "google.read-timeout");
        clientId = clientId.trim();
    }

    private static void requirePositive(Duration value, String propertyName) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(propertyName + " must be positive");
        }
    }
}
