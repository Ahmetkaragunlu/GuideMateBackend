package com.ahmetkaragunlu.guidematebackend.common.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

@Component
@Profile("prod")
public class ProductionConfigurationValidator {

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "10.0.2.2");

    private final String publicBaseUrl;

    public ProductionConfigurationValidator(@Value("${app.public-base-url}") String publicBaseUrl) {
        this.publicBaseUrl = publicBaseUrl;
    }

    @PostConstruct
    void validate() {
        URI uri = URI.create(publicBaseUrl);
        String host = uri.getHost() == null ? null : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || host == null
                || LOCAL_HOSTS.contains(host)
                || isPrivateHost(host)) {
            throw new IllegalStateException("Production PUBLIC_BASE_URL must be a public HTTPS URL");
        }
    }

    private boolean isPrivateHost(String host) {
        if (host.endsWith(".local")
                || host.startsWith("10.")
                || host.startsWith("192.168.")
                || host.startsWith("169.254.")
                || "::1".equals(host)) {
            return true;
        }

        if (!host.startsWith("172.")) {
            return false;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        try {
            int secondOctet = Integer.parseInt(parts[1]);
            return secondOctet >= 16 && secondOctet <= 31;
        } catch (NumberFormatException exception) {
            return false;
        }
    }
}
