package com.ahmetkaragunlu.guidematebackend.common.security;

import com.ahmetkaragunlu.guidematebackend.common.config.JwtProperties;
import com.ahmetkaragunlu.guidematebackend.support.MutableClock;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final Duration EXPIRATION = Duration.ofMinutes(15);
    private static final String ISSUER = "guidemate-backend";
    private static final String AUDIENCE = "guidemate-api";

    private MutableClock clock;
    private JwtService jwtService;
    private User user;
    private String secret;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-08-27T10:00:00Z"));
        secret = Base64.getEncoder().encodeToString(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)
        );
        jwtService = new JwtService(properties(ISSUER, AUDIENCE), clock);
        user = new User("Guide", "Test", "guide@example.com", "not-used");
        user.activate();
    }

    @Test
    void generatesValidTokenForActiveUser() {
        String token = jwtService.generateToken(user);

        assertThat(jwtService.extractUsername(token)).isEqualTo(user.getEmail());
        assertThat(jwtService.isTokenValid(token, user)).isTrue();
    }

    @Test
    void invalidatesTokenAfterTokenVersionChanges() {
        String token = jwtService.generateToken(user);

        user.incrementTokenVersion();

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    void invalidatesTokenWhenAccountIsDisabled() {
        String token = jwtService.generateToken(user);

        user.disable();

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    void invalidatesExpiredToken() {
        String token = jwtService.generateToken(user);
        clock.advance(EXPIRATION.plusMillis(1));

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    void rejectsTokenIssuedForAnotherTrustBoundary() {
        String token = new JwtService(properties("another-issuer", "another-api"), clock)
                .generateToken(user);

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    void rejectsLegacyTokenWithoutIssuerAndAudience() {
        Instant issuedAt = clock.instant();
        String token = Jwts.builder()
                .claim("tokenVersion", user.getTokenVersion())
                .subject(user.getUsername())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(issuedAt.plus(EXPIRATION)))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret)))
                .compact();

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    private JwtProperties properties(String issuer, String audience) {
        return new JwtProperties(
                secret,
                EXPIRATION,
                Duration.ofDays(30),
                issuer,
                audience
        );
    }
}
