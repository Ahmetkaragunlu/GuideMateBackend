package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationRealtimeResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class NotificationRealtimeEventListener {

    private static final String NOTIFICATION_DESTINATION = "/queue/notifications";

    private final SimpMessagingTemplate messagingTemplate;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onNotificationCreated(NotificationCreatedEvent event) {
        messagingTemplate.convertAndSendToUser(
                event.recipientUsername(),
                NOTIFICATION_DESTINATION,
                new NotificationRealtimeResponse(event.notificationId())
        );
    }
}
