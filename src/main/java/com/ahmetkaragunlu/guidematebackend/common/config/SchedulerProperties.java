package com.ahmetkaragunlu.guidematebackend.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "scheduler")
public record SchedulerProperties(
        int batchSize,
        Duration paymentRetryDelay,
        int paymentMaxAttempts,
        Duration refundRetryDelay,
        int refundMaxAttempts,
        Duration refundProcessingTimeout,
        Duration notificationRetryDelay,
        int notificationMaxAttempts,
        Duration reminderLeadTime,
        Duration deviceInactiveAfter,
        Duration deviceDeleteAfter
) {

    public SchedulerProperties {
        requirePositive(batchSize, "scheduler.batch-size");
        requirePositive(paymentMaxAttempts, "scheduler.payment-max-attempts");
        requirePositive(refundMaxAttempts, "scheduler.refund-max-attempts");
        requirePositive(notificationMaxAttempts, "scheduler.notification-max-attempts");
        requirePositive(paymentRetryDelay, "scheduler.payment-retry-delay");
        requirePositive(refundRetryDelay, "scheduler.refund-retry-delay");
        requirePositive(refundProcessingTimeout, "scheduler.refund-processing-timeout");
        requirePositive(notificationRetryDelay, "scheduler.notification-retry-delay");
        requirePositive(reminderLeadTime, "scheduler.reminder-lead-time");
        requirePositive(deviceInactiveAfter, "scheduler.device-inactive-after");
        requirePositive(deviceDeleteAfter, "scheduler.device-delete-after");
        if (deviceDeleteAfter != null
                && deviceInactiveAfter != null
                && deviceDeleteAfter.compareTo(deviceInactiveAfter) <= 0) {
            throw new IllegalArgumentException(
                    "scheduler.device-delete-after must be greater than device-inactive-after"
            );
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
