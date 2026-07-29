package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthRateLimitService {

    private final SecureTokenService tokenService;
    private final int loginMaxFailures;
    private final Duration loginBaseBlock;
    private final Duration loginMaxBlock;
    private final Duration loginWindow;
    private final Duration publicCooldown;

    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, Instant> publicCooldowns = new ConcurrentHashMap<>();

    public AuthRateLimitService(
            SecureTokenService tokenService,
            @Value("${auth.rate-limit.login.max-failures}") int loginMaxFailures,
            @Value("${auth.rate-limit.login.base-block-seconds}") long loginBaseBlockSeconds,
            @Value("${auth.rate-limit.login.max-block-seconds}") long loginMaxBlockSeconds,
            @Value("${auth.rate-limit.login.window-seconds}") long loginWindowSeconds,
            @Value("${auth.rate-limit.public.cooldown-seconds}") long publicCooldownSeconds
    ) {
        this.tokenService = tokenService;
        this.loginMaxFailures = loginMaxFailures;
        this.loginBaseBlock = Duration.ofSeconds(loginBaseBlockSeconds);
        this.loginMaxBlock = Duration.ofSeconds(loginMaxBlockSeconds);
        this.loginWindow = Duration.ofSeconds(loginWindowSeconds);
        this.publicCooldown = Duration.ofSeconds(publicCooldownSeconds);
    }

    public void checkLoginAllowed(String normalizedEmail, String clientIp) {
        Instant now = Instant.now();
        long retryAfter = Math.max(
                retryAfter(loginKey("email", normalizedEmail), now),
                retryAfter(loginKey("ip", clientIp), now)
        );
        if (retryAfter > 0) {
            throw new RateLimitException(retryAfter);
        }
    }

    public void recordLoginFailure(String normalizedEmail, String clientIp) {
        Instant now = Instant.now();
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
        Instant now = Instant.now();
        String emailKey = publicKey(operation, "email", normalizedEmail);
        String ipKey = publicKey(operation, "ip", clientIp);
        long retryAfter = Math.max(
                remainingSeconds(publicCooldowns.get(emailKey), now),
                remainingSeconds(publicCooldowns.get(ipKey), now)
        );
        if (retryAfter > 0) {
            throw new RateLimitException(retryAfter);
        }

        Instant blockedUntil = now.plus(publicCooldown);
        publicCooldowns.put(emailKey, blockedUntil);
        publicCooldowns.put(ipKey, blockedUntil);
    }

    @Scheduled(fixedDelayString = "${auth.rate-limit.cleanup-ms:600000}")
    public void cleanupExpiredEntries() {
        Instant now = Instant.now();
        loginAttempts.entrySet().removeIf(entry ->
                entry.getValue().lastAttempt().plus(loginWindow).isBefore(now)
                        && remainingSeconds(entry.getValue().blockedUntil(), now) == 0
        );
        publicCooldowns.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    }

    private LoginAttempt recordFailure(String key, Instant now) {
        return loginAttempts.compute(key, (ignored, previous) -> {
            int failures = previous == null || previous.lastAttempt().plus(loginWindow).isBefore(now)
                    ? 1
                    : previous.failures() + 1;
            Instant blockedUntil = failures < loginMaxFailures
                    ? null
                    : now.plus(blockDuration(failures));
            return new LoginAttempt(failures, blockedUntil, now);
        });
    }

    private Duration blockDuration(int failures) {
        int exponent = Math.min(failures - loginMaxFailures, 20);
        long multiplier = 1L << Math.max(0, exponent);
        long seconds = Math.min(loginBaseBlock.toSeconds() * multiplier, loginMaxBlock.toSeconds());
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
}
