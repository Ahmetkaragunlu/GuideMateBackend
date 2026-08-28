package com.ahmetkaragunlu.guidematebackend.media.mapper;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class MediaReferenceMapper {

    private final MediaUrlFactory mediaUrlFactory;

    public MediaReferenceResponse from(MediaAsset media) {
        return media == null ? null : fromId(media.getId());
    }

    public MediaReferenceResponse fromId(UUID mediaAssetId) {
        return mediaAssetId == null
                ? null
                : new MediaReferenceResponse(mediaAssetId, mediaUrlFactory.contentUrl(mediaAssetId));
    }
}
