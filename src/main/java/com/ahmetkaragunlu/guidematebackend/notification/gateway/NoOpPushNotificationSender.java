package com.ahmetkaragunlu.guidematebackend.notification.gateway;

import java.util.Map;

public class NoOpPushNotificationSender implements PushNotificationSender {

    @Override
    public boolean isAvailable() {
        return false;
    }

    @Override
    public PushSendResult send(String firebaseInstallationId, Map<String, String> data) {
        return PushSendResult.failed();
    }
}
