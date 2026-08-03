package com.ahmetkaragunlu.guidematebackend.media.service;

import java.util.UUID;

public interface MediaReferencePolicy {

    boolean isReferenced(UUID mediaAssetId);

    boolean isPubliclyAccessible(UUID mediaAssetId);
}
