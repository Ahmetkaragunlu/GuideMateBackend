package com.ahmetkaragunlu.guidematebackend.media.service.processing;

public record ValidatedMedia(
        String contentType,
        String fileExtension,
        String originalFileName,
        long sizeBytes
) {
}
