package com.ahmetkaragunlu.guidematebackend.notification.dto;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record NotificationResponse(
        UUID id,
        NotificationType type,
        Long actorId,
        Map<String, Object> payload,
        boolean read,
        Instant readAt,
        Instant createdAt
) {
}
