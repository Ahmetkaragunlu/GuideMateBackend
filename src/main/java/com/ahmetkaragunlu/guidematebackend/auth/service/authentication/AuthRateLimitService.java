package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.auth.config.AuthRateLimitProperties;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthRateLimitService {

    private final SecureTokenService tokenService;
    private final Clock clock;
    private final AuthRateLimitProperties properties;

    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, Instant> publicCooldowns = new ConcurrentHashMap<>();
    private final Map<String, RequestWindow> requestWindows = new ConcurrentHashMap<>();

    public AuthRateLimitService(
            SecureTokenService tokenService,
            Clock clock,
            AuthRateLimitProperties properties
    ) {
        this.tokenService = tokenService;
        this.clock = clock;
        this.properties = properties;
    }

    public void checkLoginAllowed(String normalizedEmail, String clientIp) {
        Instant now = clock.instant();
        long retryAfter = Math.max(
                retryAfter(loginKey("email", normalizedEmail), now),
                retryAfter(loginKey("ip", clientIp), now)
        );
        if (retryAfter > 0) {
            throw new RateLimitException(retryAfter);
        }
    }

    public void recordLoginFailure(String normalizedEmail, String clientIp) {
        Instant now = clock.instant();
        LoginAttempt emailAttempt = recordFailure(loginKey("email", normalizedEmail), now);
        LoginAttempt ipAttempt = recordFailure(loginKey("ip", clientIp), now);
        long retryAfter = Math.max(
                remainingSeconds(emailAttempt.blockedUntil(), now),
                remainingSeconds(ipAttempt.blockedUntil(), now)
        );
        if (retryAfter > 0) {
            throw new RateLimitException(retryAfter);
        }
    }

    public void recordLoginSuccess(String normalizedEmail, String clientIp) {
        loginAttempts.remove(loginKey("email", normalizedEmail));
        loginAttempts.remove(loginKey("ip", clientIp));
    }

    public synchronized void acquirePublicPermit(String operation, String normalizedEmail, String clientIp) {
        Instant now = clock.instant();
        String emailKey = publicKey(operation, "email", normalizedEmail);
        String ipKey = publicKey(operation, "ip", clientIp);
        long retryAfter = Math.max(
                remainingSeconds(publicCooldowns.get(emailKey), now),
                remainingSeconds(publicCooldowns.get(ipKey), now)
        );
        if (retryAfter > 0) {
            throw new RateLimitException(retryAfter);
        }

        Instant blockedUntil = now.plus(properties.publicOperations().cooldown());
        publicCooldowns.put(emailKey, blockedUntil);
        publicCooldowns.put(ipKey, blockedUntil);
    }

    public void acquireRegistrationPermit(String normalizedEmail, String clientIp) {
        AuthRateLimitProperties.Register registerLimit = properties.register();
        acquireRequestPermit(
                "register",
                "email",
                normalizedEmail,
                registerLimit.maxPerEmail(),
                clientIp,
                registerLimit.maxPerIp(),
                registerLimit.window()
        );
    }

    public void acquireGoogleLoginPermit(String installationId, String clientIp) {
        AuthRateLimitProperties.GoogleLogin googleLoginLimit = properties.googleLogin();
        acquireRequestPermit(
                "google-login",
                "installation",
                installationId,
                googleLoginLimit.maxPerInstallation(),
                clientIp,
                googleLoginLimit.maxPerIp(),
                googleLoginLimit.window()
        );
    }

    @Scheduled(fixedDelayString = "${auth.rate-limit.cleanup-interval:PT10M}")
    public void cleanupExpiredEntries() {
        Instant now = clock.instant();
        loginAttempts.entrySet().removeIf(entry ->
                entry.getValue().lastAttempt().plus(properties.login().window()).isBefore(now)
                        && remainingSeconds(entry.getValue().blockedUntil(), now) == 0
        );
        publicCooldowns.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
        requestWindows.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    private synchronized void acquireRequestPermit(
            String operation,
            String identityType,
            String identity,
            int identityLimit,
            String clientIp,
            int ipLimit,
            Duration windowDuration
    ) {
        Instant now = clock.instant();
        String identityKey = publicKey(operation, identityType, identity);
        String ipKey = publicKey(operation, "ip", clientIp);
        RequestWindow identityWindow = currentWindow(identityKey, now, windowDuration);
        RequestWindow ipWindow = currentWindow(ipKey, now, windowDuration);

        long retryAfter = Math.max(
                retryAfter(identityWindow, identityLimit, now),
                retryAfter(ipWindow, ipLimit, now)
        );
        if (retryAfter > 0) {
            throw new RateLimitException(retryAfter);
        }

        requestWindows.put(identityKey, identityWindow.increment());
        requestWindows.put(ipKey, ipWindow.increment());
    }

    private RequestWindow currentWindow(String key, Instant now, Duration duration) {
        RequestWindow current = requestWindows.get(key);
        if (current == null || !current.expiresAt().isAfter(now)) {
            return new RequestWindow(0, now.plus(duration));
        }
        return current;
    }

    private long retryAfter(RequestWindow window, int limit, Instant now) {
        return window.count() < limit ? 0 : remainingSeconds(window.expiresAt(), now);
    }

    private LoginAttempt recordFailure(String key, Instant now) {
        AuthRateLimitProperties.Login login = properties.login();
        return loginAttempts.compute(key, (ignored, previous) -> {
            int failures = previous == null || previous.lastAttempt().plus(login.window()).isBefore(now)
                    ? 1
                    : previous.failures() + 1;
            Instant blockedUntil = failures < login.maxFailures()
                    ? null
                    : now.plus(blockDuration(failures, login));
            return new LoginAttempt(failures, blockedUntil, now);
        });
    }

    private Duration blockDuration(int failures, AuthRateLimitProperties.Login login) {
        int exponent = Math.min(failures - login.maxFailures(), 20);
        long multiplier = 1L << Math.max(0, exponent);
        long seconds = Math.min(
                login.baseBlock().toSeconds() * multiplier,
                login.maxBlock().toSeconds()
        );
        return Duration.ofSeconds(seconds);
    }

    private long retryAfter(String key, Instant now) {
        LoginAttempt attempt = loginAttempts.get(key);
        return attempt == null ? 0 : remainingSeconds(attempt.blockedUntil(), now);
    }

    private long remainingSeconds(Instant blockedUntil, Instant now) {
        if (blockedUntil == null || !blockedUntil.isAfter(now)) {
            return 0;
        }
        return Math.max(1, Duration.between(now, blockedUntil).toSeconds());
    }

    private String loginKey(String type, String value) {
        return tokenService.hash("login:" + type + ":" + value);
    }

    private String publicKey(String operation, String type, String value) {
        return tokenService.hash(operation + ":" + type + ":" + value);
    }

    private record LoginAttempt(int failures, Instant blockedUntil, Instant lastAttempt) {
    }

    private record RequestWindow(int count, Instant expiresAt) {

        private RequestWindow increment() {
            return new RequestWindow(count + 1, expiresAt);
        }
    }
}
