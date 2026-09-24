package com.ahmetkaragunlu.guidematebackend.common.security.jwt;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        Duration expiration,
        Duration refreshExpiration,
        String issuer,
        String audience
) {

    private static final int MINIMUM_SECRET_BYTES = 32;

    public JwtProperties {
        if (isBlank(secret)) {
            throw new IllegalArgumentException("jwt.secret is required");
        }
        byte[] decodedSecret;
        try {
            decodedSecret = Decoders.BASE64.decode(secret);
        } catch (DecodingException exception) {
            throw new IllegalArgumentException("jwt.secret must be valid Base64", exception);
        }
        if (decodedSecret.length < MINIMUM_SECRET_BYTES) {
            throw new IllegalArgumentException("jwt.secret must contain at least 32 bytes");
        }
        requirePositive(expiration, "jwt.expiration");
        requirePositive(refreshExpiration, "jwt.refresh-expiration");
        if (refreshExpiration.compareTo(expiration) <= 0) {
            throw new IllegalArgumentException("jwt.refresh-expiration must be greater than jwt.expiration");
        }
        if (isBlank(issuer) || isBlank(audience)) {
            throw new IllegalArgumentException("jwt.issuer and jwt.audience are required");
        }
        issuer = issuer.trim();
        audience = audience.trim();
    }

    private static void requirePositive(Duration value, String propertyName) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(propertyName + " must be positive");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
