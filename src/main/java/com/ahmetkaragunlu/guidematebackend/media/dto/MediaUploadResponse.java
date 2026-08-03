package com.ahmetkaragunlu.guidematebackend.media.dto;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaStatus;

import java.util.UUID;

public record MediaUploadResponse(
        UUID mediaAssetId,
        MediaPurpose purpose,
        MediaStatus status,
        String imageUrl,
        String contentType,
        long sizeBytes
) {
}
