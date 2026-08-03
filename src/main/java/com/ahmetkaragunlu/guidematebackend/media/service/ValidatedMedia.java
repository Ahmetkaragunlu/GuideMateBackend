package com.ahmetkaragunlu.guidematebackend.media.service;

public record ValidatedMedia(
        String contentType,
        String fileExtension,
        String originalFileName,
        long sizeBytes
) {
}
