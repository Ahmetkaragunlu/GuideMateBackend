package com.ahmetkaragunlu.guidematebackend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "auth.rate-limit")
public record AuthRateLimitProperties(
        Login login,
        PublicOperations publicOperations,
        Register register,
        GoogleLogin googleLogin,
        Duration cleanupInterval
) {

    public AuthRateLimitProperties {
        if (login == null || publicOperations == null || register == null || googleLogin == null) {
            throw new IllegalArgumentException("Auth rate-limit configuration is incomplete");
        }
        requirePositive(cleanupInterval, "auth.rate-limit.cleanup-interval");
    }

    public record Login(
            int maxFailures,
            Duration baseBlock,
            Duration maxBlock,
            Duration window
    ) {
        public Login {
            if (maxFailures <= 0) {
                throw new IllegalArgumentException("auth.rate-limit.login.max-failures must be positive");
            }
            requirePositive(baseBlock, "auth.rate-limit.login.base-block");
            requirePositive(maxBlock, "auth.rate-limit.login.max-block");
            requirePositive(window, "auth.rate-limit.login.window");
            if (baseBlock != null && maxBlock != null && maxBlock.compareTo(baseBlock) < 0) {
                throw new IllegalArgumentException(
                        "auth.rate-limit.login.max-block must not be less than base-block"
                );
            }
        }
    }

    public record PublicOperations(Duration cooldown) {
        public PublicOperations {
            requirePositive(cooldown, "auth.rate-limit.public-operations.cooldown");
        }
    }

    public record Register(int maxPerEmail, int maxPerIp, Duration window) {
        public Register {
            requirePositive(maxPerEmail, "auth.rate-limit.register.max-per-email");
            requirePositive(maxPerIp, "auth.rate-limit.register.max-per-ip");
            requirePositive(window, "auth.rate-limit.register.window");
        }
    }

    public record GoogleLogin(int maxPerInstallation, int maxPerIp, Duration window) {
        public GoogleLogin {
            requirePositive(maxPerInstallation, "auth.rate-limit.google-login.max-per-installation");
            requirePositive(maxPerIp, "auth.rate-limit.google-login.max-per-ip");
            requirePositive(window, "auth.rate-limit.google-login.window");
        }
    }

    private static void requirePositive(int value, String propertyName) {
        if (value <= 0) {
            throw new IllegalArgumentException(propertyName + " must be positive");
        }
    }

    private static void requirePositive(Duration value, String propertyName) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(propertyName + " must be positive");
        }
    }
}
