package com.ahmetkaragunlu.guidematebackend.common.config.scheduling;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SchedulerPropertiesTest {

    @Test
    void rejectsNonPositiveLimitsAndDurations() {
        assertThatThrownBy(() -> createProperties(0, Duration.ofMinutes(1), Duration.ofDays(90)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> createProperties(25, Duration.ZERO, Duration.ofDays(90)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requiresDeleteCutoffAfterInactiveCutoff() {
        assertThatThrownBy(() -> createProperties(25, Duration.ofMinutes(1), Duration.ofDays(30)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("device-delete-after");
    }

    private void createProperties(int batchSize, Duration retryDelay, Duration deleteAfter) {
        new SchedulerProperties(
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
