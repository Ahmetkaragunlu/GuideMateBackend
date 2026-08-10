package com.ahmetkaragunlu.guidematebackend.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security")
public record DataProtectionProperties(String dataProtectionKey) {

    public DataProtectionProperties {
        if (dataProtectionKey == null || dataProtectionKey.isBlank()) {
            throw new IllegalArgumentException("security.data-protection-key is required");
        }
    }
}
