package com.ahmetkaragunlu.guidematebackend.common.security;

import com.ahmetkaragunlu.guidematebackend.support.MutableClock;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final long EXPIRATION_MILLIS = Duration.ofMinutes(15).toMillis();

    private MutableClock clock;
    private JwtService jwtService;
    private User user;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-08-27T10:00:00Z"));
        String secret = Base64.getEncoder().encodeToString(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)
        );
        jwtService = new JwtService(secret, EXPIRATION_MILLIS, clock);
        user = new User();
        user.setEmail("guide@example.com");
        user.setPassword("not-used");
        user.setAccountStatus(AccountStatus.ACTIVE);
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

        user.setAccountStatus(AccountStatus.DISABLED);

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    void invalidatesExpiredToken() {
        String token = jwtService.generateToken(user);
        clock.advance(Duration.ofMillis(EXPIRATION_MILLIS + 1));

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }
}
