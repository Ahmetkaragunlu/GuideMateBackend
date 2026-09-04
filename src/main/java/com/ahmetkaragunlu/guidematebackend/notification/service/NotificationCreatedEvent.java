package com.ahmetkaragunlu.guidematebackend.notification.service;

import java.util.UUID;

public record NotificationCreatedEvent(
        UUID notificationId,
        String recipientUsername,
        boolean pushRequested
) {
}
