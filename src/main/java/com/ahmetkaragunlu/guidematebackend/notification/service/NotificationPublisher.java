package com.ahmetkaragunlu.guidematebackend.notification.service;

import java.util.UUID;

public interface NotificationPublisher {

    UUID publish(NotificationCommand command);
}
