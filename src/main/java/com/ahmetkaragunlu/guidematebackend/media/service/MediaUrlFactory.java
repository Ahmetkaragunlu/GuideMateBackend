package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.config.AppProperties;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class MediaUrlFactory {

    private final String publicBaseUrl;

    public MediaUrlFactory(AppProperties properties) {
        this.publicBaseUrl = properties.publicBaseUrl().toString();
    }

    public String contentUrl(UUID mediaAssetId) {
        return publicBaseUrl + "/api/v1/media/" + mediaAssetId + "/content";
    }
}
