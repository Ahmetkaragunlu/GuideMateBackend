package com.ahmetkaragunlu.guidematebackend.notification.dto;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationTargetType;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record MarkRelatedNotificationsReadRequest(
        @NotNull NotificationTargetType targetType,
        @NotNull UUID targetId
) {
}
