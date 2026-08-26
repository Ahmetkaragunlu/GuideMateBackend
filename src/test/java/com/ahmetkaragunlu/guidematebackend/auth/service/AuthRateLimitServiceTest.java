package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthRateLimitServiceTest {

    private static final String EMAIL = "tourist@example.com";
    private static final String CLIENT_IP = "203.0.113.10";

    private MutableClock clock;
    private AuthRateLimitService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-08-27T10:00:00Z"));
        service = new AuthRateLimitService(
                new SecureTokenService(),
                clock,
                3,
                10,
                40,
                60,
                30
        );
    }

    @Test
    void blocksLoginAtConfiguredFailureThreshold() {
        service.recordLoginFailure(EMAIL, CLIENT_IP);
        service.recordLoginFailure(EMAIL, CLIENT_IP);

        assertThatThrownBy(() -> service.recordLoginFailure(EMAIL, CLIENT_IP))
                .isInstanceOfSatisfying(RateLimitException.class, exception ->
                        assertThat(exception.getRetryAfterSeconds()).isEqualTo(10));
        assertThatThrownBy(() -> service.checkLoginAllowed(EMAIL, CLIENT_IP))
                .isInstanceOf(RateLimitException.class);
    }

    @Test
    void exponentiallyIncreasesBlockAndCapsIt() {
        reachFailureThreshold();

        assertNextBlockAfter(Duration.ofSeconds(10), 20);
        assertNextBlockAfter(Duration.ofSeconds(20), 40);
        assertNextBlockAfter(Duration.ofSeconds(40), 40);
    }

    @Test
    void successfulLoginResetsEmailAndIpAttempts() {
        reachFailureThreshold();

        service.recordLoginSuccess(EMAIL, CLIENT_IP);

        assertThatCode(() -> service.checkLoginAllowed(EMAIL, CLIENT_IP)).doesNotThrowAnyException();
        assertThatCode(() -> service.recordLoginFailure(EMAIL, CLIENT_IP)).doesNotThrowAnyException();
    }

    @Test
    void failuresOutsideWindowStartANewAttemptSequence() {
        service.recordLoginFailure(EMAIL, CLIENT_IP);
        service.recordLoginFailure(EMAIL, CLIENT_IP);
        clock.advance(Duration.ofSeconds(61));

        assertThatCode(() -> service.recordLoginFailure(EMAIL, CLIENT_IP)).doesNotThrowAnyException();
        assertThatCode(() -> service.recordLoginFailure(EMAIL, CLIENT_IP)).doesNotThrowAnyException();
    }

    @Test
    void publicOperationPermitIsScopedByOperationAndEnforcesIpCooldown() {
        service.acquirePublicPermit("forgot-password", EMAIL, CLIENT_IP);

        assertThatThrownBy(() -> service.acquirePublicPermit(
                "forgot-password",
                "another@example.com",
                CLIENT_IP
        )).isInstanceOf(RateLimitException.class);
        assertThatCode(() -> service.acquirePublicPermit("resend-confirmation", EMAIL, CLIENT_IP))
                .doesNotThrowAnyException();

        clock.advance(Duration.ofSeconds(30));

        assertThatCode(() -> service.acquirePublicPermit("forgot-password", EMAIL, CLIENT_IP))
                .doesNotThrowAnyException();
    }

    private void reachFailureThreshold() {
        service.recordLoginFailure(EMAIL, CLIENT_IP);
        service.recordLoginFailure(EMAIL, CLIENT_IP);
        try {
            service.recordLoginFailure(EMAIL, CLIENT_IP);
        } catch (RateLimitException ignored) {
            // Reaching the threshold both records the failure and reports the block.
        }
    }

    private void assertNextBlockAfter(Duration elapsed, long expectedRetryAfterSeconds) {
        clock.advance(elapsed);

        assertThatThrownBy(() -> service.recordLoginFailure(EMAIL, CLIENT_IP))
                .isInstanceOfSatisfying(RateLimitException.class, exception ->
                        assertThat(exception.getRetryAfterSeconds()).isEqualTo(expectedRetryAfterSeconds));
    }
}
