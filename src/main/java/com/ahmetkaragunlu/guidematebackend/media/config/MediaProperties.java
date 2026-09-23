package com.ahmetkaragunlu.guidematebackend.media.config;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;
import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "media")
public record MediaProperties(
        @NotNull Path storageRoot,
        @NotNull DataSize maxFileSize,
        @NotNull Duration orphanGracePeriod,
        int maxImageWidth,
        int maxImageHeight,
        long maxImagePixels
) {

    public MediaProperties {
        if (maxFileSize != null && maxFileSize.toBytes() <= 0) {
            throw new IllegalArgumentException("media.max-file-size must be positive");
        }
        if (orphanGracePeriod != null && (orphanGracePeriod.isNegative() || orphanGracePeriod.isZero())) {
            throw new IllegalArgumentException("media.orphan-grace-period must be positive");
        }
        if (maxImageWidth <= 0 || maxImageHeight <= 0 || maxImagePixels <= 0) {
            throw new IllegalArgumentException("media image dimensions must be positive");
        }
    }
}
