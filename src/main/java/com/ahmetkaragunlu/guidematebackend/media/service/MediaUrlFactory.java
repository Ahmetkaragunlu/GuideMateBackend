package com.ahmetkaragunlu.guidematebackend.media.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Set;
import java.util.UUID;

@Component
public class MediaUrlFactory {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private final String publicBaseUrl;

    public MediaUrlFactory(@Value("${app.public-base-url}") String publicBaseUrl) {
        URI uri = URI.create(publicBaseUrl);
        if (!uri.isAbsolute() || uri.getHost() == null || !ALLOWED_SCHEMES.contains(uri.getScheme())) {
            throw new IllegalStateException("PUBLIC_BASE_URL must be an absolute HTTP(S) URL");
        }
        this.publicBaseUrl = publicBaseUrl.replaceAll("/+$", "");
    }

    public String contentUrl(UUID mediaAssetId) {
        return publicBaseUrl + "/api/v1/media/" + mediaAssetId + "/content";
    }
}
