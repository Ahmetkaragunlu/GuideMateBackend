package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;

import java.util.Map;
import java.util.Objects;

public record NotificationCommand(
        Long recipientId,
        NotificationType type,
        Long actorId,
        Map<String, Object> payload,
        String deduplicationKey
) {
    public NotificationCommand(
            Long recipientId,
            NotificationType type,
            Long actorId,
            Map<String, Object> payload
    ) {
        this(recipientId, type, actorId, payload, null);
    }

    public NotificationCommand {
        Objects.requireNonNull(recipientId, "recipientId must not be null");
        Objects.requireNonNull(type, "type must not be null");
        payload = Map.copyOf(Objects.requireNonNull(payload, "payload must not be null"));
        if (deduplicationKey != null) {
            deduplicationKey = deduplicationKey.trim();
            if (deduplicationKey.isEmpty() || deduplicationKey.length() > 160) {
                throw new IllegalArgumentException("deduplicationKey must contain 1 to 160 characters");
            }
        }
    }
}
