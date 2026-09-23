package com.ahmetkaragunlu.guidematebackend.media.service;

import java.util.Arrays;
import java.util.Objects;

public record ProcessedMedia(byte[] content, ValidatedMedia metadata) {

    public ProcessedMedia {
        Objects.requireNonNull(content, "content must not be null");
        Objects.requireNonNull(metadata, "metadata must not be null");
        content = Arrays.copyOf(content, content.length);
    }

    @Override
    public byte[] content() {
        return Arrays.copyOf(content, content.length);
    }
}
