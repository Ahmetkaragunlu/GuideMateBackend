package com.ahmetkaragunlu.guidematebackend.notification.gateway;

import java.util.Map;

public interface PushNotificationSender {

    boolean isAvailable();

    PushSendResult send(String firebaseInstallationId, Map<String, String> data);
}
