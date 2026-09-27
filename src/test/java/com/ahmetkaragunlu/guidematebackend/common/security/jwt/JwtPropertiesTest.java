package com.ahmetkaragunlu.guidematebackend.common.security.jwt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtPropertiesTest {

    private static final String VALID_SECRET = Base64.getEncoder().encodeToString(
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)
    );

    @Test
    void acceptsValidConfigurationAndNormalizesTrustBoundaryNames() {
        JwtProperties properties = new JwtProperties(
                VALID_SECRET,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                " guidemate-backend ",
                " guidemate-api "
        );

        assertThat(properties.issuer()).isEqualTo("guidemate-backend");
        assertThat(properties.audience()).isEqualTo("guidemate-api");
    }

    @Test
    void rejectsInvalidOrWeakSecret() {
        assertThatThrownBy(() -> createProperties("not-base64", Duration.ofDays(30)))
                .isInstanceOf(IllegalArgumentException.class);

        String weakSecret = Base64.getEncoder().encodeToString("too-short".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> new JwtProperties(
                weakSecret,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                "guidemate-backend",
                "guidemate-api"
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonPositiveOrNonIncreasingDurations() {
        assertThatThrownBy(() -> new JwtProperties(
                VALID_SECRET,
                Duration.ZERO,
                Duration.ofDays(30),
                "guidemate-backend",
                "guidemate-api"
        )).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> createProperties(VALID_SECRET, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMissingIssuerOrAudience() {
        assertThatThrownBy(() -> new JwtProperties(
                VALID_SECRET,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                " ",
                "guidemate-api"
        )).isInstanceOf(IllegalArgumentException.class);
    }

    private void createProperties(String secret, Duration refreshExpiration) {
        new JwtProperties(
                secret,
                Duration.ofMinutes(15),
                refreshExpiration,
                "guidemate-backend",
                "guidemate-api"
        );
    }
}
