package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationRealtimeResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.util.UUID;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class NotificationRealtimeEventListenerTest {

    @Mock
    private SimpMessagingTemplate messagingTemplate;

    @Test
    void sendsNotificationEventOnlyToItsRecipient() {
        UUID notificationId = UUID.randomUUID();
        var listener = new NotificationRealtimeEventListener(messagingTemplate);

        listener.onNotificationCreated(new NotificationCreatedEvent(
                notificationId,
                "recipient@example.com",
                true
        ));

        verify(messagingTemplate).convertAndSendToUser(
                "recipient@example.com",
                "/queue/notifications",
                new NotificationRealtimeResponse(notificationId)
        );
    }
}
