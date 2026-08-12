package com.ahmetkaragunlu.guidematebackend.demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "demo.seed")
public record DemoSeedProperties(
        boolean enabled,
        String password,
        String guideEmail,
        String touristEmail
) {

    public DemoSeedProperties {
        if (enabled && (isBlank(password) || isBlank(guideEmail) || isBlank(touristEmail))) {
            throw new IllegalArgumentException(
                    "Demo seed password, guide email and tourist email are required when enabled"
            );
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
