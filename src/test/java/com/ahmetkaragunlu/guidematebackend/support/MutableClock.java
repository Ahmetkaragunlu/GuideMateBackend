package com.ahmetkaragunlu.guidematebackend.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Objects;

public final class MutableClock extends Clock {

    private Instant currentInstant;
    private final ZoneId zone;

    public MutableClock(Instant currentInstant) {
        this(currentInstant, ZoneOffset.UTC);
    }

    private MutableClock(Instant currentInstant, ZoneId zone) {
        this.currentInstant = Objects.requireNonNull(currentInstant);
        this.zone = Objects.requireNonNull(zone);
    }

    public void advance(Duration duration) {
        currentInstant = currentInstant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new MutableClock(currentInstant, zone);
    }

    @Override
    public Instant instant() {
        return currentInstant;
    }
}
