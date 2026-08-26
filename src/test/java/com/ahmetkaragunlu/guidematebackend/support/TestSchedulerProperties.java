package com.ahmetkaragunlu.guidematebackend.support;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;

import java.time.Duration;

public final class TestSchedulerProperties {

    private TestSchedulerProperties() {
    }

    public static SchedulerProperties defaults() {
        return new SchedulerProperties(
                25,
                Duration.ofMinutes(2),
                5,
                Duration.ofMinutes(3),
                4,
                Duration.ofMinutes(10),
                Duration.ofMinutes(2),
                6,
                Duration.ofHours(24),
                Duration.ofDays(30),
                Duration.ofDays(90)
        );
    }
}
