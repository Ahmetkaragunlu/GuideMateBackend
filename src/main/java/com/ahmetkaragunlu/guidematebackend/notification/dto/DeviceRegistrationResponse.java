package com.ahmetkaragunlu.guidematebackend.notification.dto;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DevicePlatform;

import java.time.Instant;
import java.util.UUID;

public record DeviceRegistrationResponse(
        UUID id,
        UUID installationId,
        DevicePlatform platform,
        boolean active,
        Instant lastSeenAt
) {
}
