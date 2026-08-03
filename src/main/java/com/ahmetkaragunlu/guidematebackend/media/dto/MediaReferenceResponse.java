package com.ahmetkaragunlu.guidematebackend.media.dto;

import java.util.UUID;

public record MediaReferenceResponse(
        UUID mediaAssetId,
        String imageUrl
) {
}
