package com.ahmetkaragunlu.guidematebackend.common.config.scheduling;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SchedulerPropertiesTest {

    @Test
    void rejectsNonPositiveLimitsAndDurations() {
        assertThatThrownBy(() -> properties(0, Duration.ofMinutes(1), Duration.ofDays(90)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(25, Duration.ZERO, Duration.ofDays(90)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requiresDeleteCutoffAfterInactiveCutoff() {
        assertThatThrownBy(() -> properties(25, Duration.ofMinutes(1), Duration.ofDays(30)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("device-delete-after");
    }

    private SchedulerProperties properties(int batchSize, Duration retryDelay, Duration deleteAfter) {
        return new SchedulerProperties(
                batchSize,
                retryDelay,
                5,
                Duration.ofMinutes(1),
                5,
                Duration.ofMinutes(5),
                Duration.ofMinutes(1),
                5,
                Duration.ofHours(24),
                Duration.ofDays(30),
                deleteAfter
        );
    }
}
