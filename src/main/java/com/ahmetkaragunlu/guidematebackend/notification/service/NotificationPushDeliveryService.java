package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.gateway.PushNotificationSender;
import com.ahmetkaragunlu.guidematebackend.notification.gateway.PushSendResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class NotificationPushDeliveryService {

    private final NotificationPushDeliveryStateService stateService;
    private final PushNotificationSender pushNotificationSender;

    public void deliver(UUID notificationId) {
        NotificationPushDeliveryStateService.PushAttempt attempt = stateService.begin(
                notificationId,
                pushNotificationSender.isAvailable()
        );
        if (attempt == null) {
            return;
        }

        boolean delivered = false;
        Set<UUID> invalidRegistrationIds = new HashSet<>();
        for (NotificationPushDeliveryStateService.PushTarget target : attempt.targets()) {
            PushSendResult result = pushNotificationSender.send(
                    target.firebaseInstallationId(),
                    attempt.data()
            );
            delivered = delivered || result.delivered();
            if (result.registrationInvalid()) {
                invalidRegistrationIds.add(target.registrationId());
            }
        }
        stateService.complete(attempt.notificationId(), invalidRegistrationIds, delivered);
    }
}
