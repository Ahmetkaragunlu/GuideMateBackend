package com.ahmetkaragunlu.guidematebackend.user.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.admin-seed")
public record AdminAccountSeedProperties(
        boolean enabled,
        String email,
        String password,
        String firstName,
        String lastName
) {

    public AdminAccountSeedProperties {
        if (enabled) {
            requireText(email, "ADMIN_EMAIL");
            requireText(password, "ADMIN_PASSWORD");
            requireText(firstName, "ADMIN_FIRST_NAME");
            requireText(lastName, "ADMIN_LAST_NAME");
        }
    }

    private static void requireText(String value, String environmentVariable) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(environmentVariable + " is required when admin seed is enabled");
        }
    }
}
