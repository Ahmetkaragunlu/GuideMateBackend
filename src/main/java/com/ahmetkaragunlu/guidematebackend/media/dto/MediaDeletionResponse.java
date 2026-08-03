package com.ahmetkaragunlu.guidematebackend.media.dto;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaStatus;

import java.util.UUID;

public record MediaDeletionResponse(
        UUID mediaAssetId,
        MediaStatus status
) {
}
