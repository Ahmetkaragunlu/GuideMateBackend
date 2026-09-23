package com.ahmetkaragunlu.guidematebackend.media.config;

import org.junit.jupiter.api.Test;
import org.springframework.util.unit.DataSize;

import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MediaPropertiesTest {

    @Test
    void rejectsNonPositiveStorageLimits() {
        assertThatThrownBy(() -> new MediaProperties(
                Path.of("build/media"),
                DataSize.ofBytes(0),
                Duration.ofHours(1),
                1024,
                1024,
                1_048_576
        )).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new MediaProperties(
                Path.of("build/media"),
                DataSize.ofMegabytes(5),
                Duration.ofHours(1),
                0,
                1024,
                1_048_576
        )).isInstanceOf(IllegalArgumentException.class);
    }
}
