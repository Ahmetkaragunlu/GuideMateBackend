package com.ahmetkaragunlu.guidematebackend.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

@ConfigurationProperties(prefix = "app")
public record AppProperties(URI publicBaseUrl) {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    public AppProperties {
        if (publicBaseUrl == null
                || !publicBaseUrl.isAbsolute()
                || publicBaseUrl.getHost() == null
                || !ALLOWED_SCHEMES.contains(publicBaseUrl.getScheme().toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("PUBLIC_BASE_URL must be an absolute HTTP(S) URL");
        }
        publicBaseUrl = URI.create(publicBaseUrl.toString().replaceAll("/+$", ""));
    }
}
