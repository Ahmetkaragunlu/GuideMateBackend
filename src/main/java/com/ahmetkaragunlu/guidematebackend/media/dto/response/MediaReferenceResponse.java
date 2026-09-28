package com.ahmetkaragunlu.guidematebackend.media.dto.response;

import java.util.UUID;

public record MediaReferenceResponse(
        UUID mediaAssetId,
        String imageUrl
) {
}
