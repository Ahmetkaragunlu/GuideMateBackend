package com.ahmetkaragunlu.guidematebackend.demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Instant;

@ConfigurationProperties(prefix = "demo.dataset")
public record DemoDatasetProperties(
        boolean enabled,
        String password,
        Instant referenceInstant
) {

    public DemoDatasetProperties {
        if (enabled && (password == null || password.isBlank())) {
            throw new IllegalArgumentException("Demo dataset password is required when enabled");
        }
        if (enabled && referenceInstant == null) {
            throw new IllegalArgumentException("Demo dataset reference instant is required when enabled");
        }
    }
}
