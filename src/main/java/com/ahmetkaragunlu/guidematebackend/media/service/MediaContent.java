package com.ahmetkaragunlu.guidematebackend.media.service;

public record MediaContent(
        byte[] bytes,
        String contentType,
        boolean publiclyAccessible
) {
}
