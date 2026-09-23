package com.ahmetkaragunlu.guidematebackend.notification.event;

import java.util.UUID;

public record NotificationCreatedEvent(
        UUID notificationId,
        String recipientUsername,
        boolean pushRequested
) {
}
