package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.auth.config.AuthRateLimitProperties;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
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
                new AuthRateLimitProperties(
                        new AuthRateLimitProperties.Login(
                                3,
                                Duration.ofSeconds(10),
                                Duration.ofSeconds(40),
                                Duration.ofSeconds(60)
                        ),
                        new AuthRateLimitProperties.PublicOperations(Duration.ofSeconds(30)),
                        new AuthRateLimitProperties.Register(2, 3, Duration.ofSeconds(60)),
                        new AuthRateLimitProperties.GoogleLogin(2, 3, Duration.ofSeconds(60)),
                        Duration.ofMinutes(10)
                )
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

    @Test
    void registrationLimitsEmailAndIpIndependentlyWithoutConsumingPartialPermit() {
        service.acquireRegistrationPermit(EMAIL, CLIENT_IP);
        service.acquireRegistrationPermit(EMAIL, "203.0.113.11");

        assertThatThrownBy(() -> service.acquireRegistrationPermit(EMAIL, "203.0.113.12"))
                .isInstanceOf(RateLimitException.class);

        service.acquireRegistrationPermit("another@example.com", "203.0.113.12");
        service.acquireRegistrationPermit("third@example.com", CLIENT_IP);
        service.acquireRegistrationPermit("fourth@example.com", CLIENT_IP);

        assertThatThrownBy(() -> service.acquireRegistrationPermit("fifth@example.com", CLIENT_IP))
                .isInstanceOf(RateLimitException.class);
    }

    @Test
    void googleLoginWindowResetsAfterConfiguredDuration() {
        service.acquireGoogleLoginPermit("installation-1", CLIENT_IP);
        service.acquireGoogleLoginPermit("installation-1", CLIENT_IP);

        assertThatThrownBy(() -> service.acquireGoogleLoginPermit("installation-1", CLIENT_IP))
                .isInstanceOf(RateLimitException.class);

        clock.advance(Duration.ofSeconds(60));

        assertThatCode(() -> service.acquireGoogleLoginPermit("installation-1", CLIENT_IP))
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
