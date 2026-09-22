package com.ahmetkaragunlu.guidematebackend.auth.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthConfigurationPropertiesTest {

    @Test
    void rejectsInvalidLoginRateLimitConfiguration() {
        assertThatThrownBy(() -> new AuthRateLimitProperties.Login(
                5,
                Duration.ofMinutes(2),
                Duration.ofMinutes(1),
                Duration.ofMinutes(15)
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsInvalidPublicOrCleanupDurations() {
        AuthRateLimitProperties.Login login = new AuthRateLimitProperties.Login(
                5,
                Duration.ofSeconds(30),
                Duration.ofMinutes(15),
                Duration.ofMinutes(15)
        );

        assertThatThrownBy(() -> new AuthRateLimitProperties(
                login,
                new AuthRateLimitProperties.PublicOperations(Duration.ZERO),
                Duration.ofMinutes(10)
        )).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new AuthRateLimitProperties(
                login,
                new AuthRateLimitProperties.PublicOperations(Duration.ofMinutes(1)),
                Duration.ZERO
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsIncompleteGoogleConfiguration() {
        assertThatThrownBy(() -> new GoogleAuthProperties(
                " ",
                Duration.ofSeconds(3),
                Duration.ofSeconds(5)
        )).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new GoogleAuthProperties(
                "client.apps.googleusercontent.com",
                Duration.ZERO,
                Duration.ofSeconds(5)
        )).isInstanceOf(IllegalArgumentException.class);
    }
}
