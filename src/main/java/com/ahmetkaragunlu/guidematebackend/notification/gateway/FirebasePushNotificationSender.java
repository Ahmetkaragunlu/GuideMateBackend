package com.ahmetkaragunlu.guidematebackend.notification.gateway;

import com.google.firebase.messaging.AndroidConfig;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.MessagingErrorCode;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public class FirebasePushNotificationSender implements PushNotificationSender {

    private final FirebaseMessaging firebaseMessaging;

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public PushSendResult send(String firebaseInstallationId, Map<String, String> data) {
        Message message = Message.builder()
                .setFid(firebaseInstallationId)
                .putAllData(data)
                .setAndroidConfig(AndroidConfig.builder()
                        .setPriority(AndroidConfig.Priority.HIGH)
                        .build())
                .build();
        try {
            firebaseMessaging.send(message);
            return PushSendResult.sent();
        } catch (FirebaseMessagingException exception) {
            if (exception.getMessagingErrorCode() == MessagingErrorCode.UNREGISTERED) {
                return PushSendResult.invalidRegistration();
            }
            return PushSendResult.failed();
        }
    }
}
