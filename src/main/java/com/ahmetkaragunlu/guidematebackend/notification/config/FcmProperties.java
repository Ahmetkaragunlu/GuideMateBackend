package com.ahmetkaragunlu.guidematebackend.notification.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "notification.fcm")
public record FcmProperties(boolean enabled, String credentialsPath) {
}
