package com.ahmetkaragunlu.guidematebackend.notification.event;

import com.ahmetkaragunlu.guidematebackend.notification.service.delivery.NotificationPushDeliveryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class NotificationPushDeliveryEventListenerTest {

    @Mock
    private NotificationPushDeliveryService deliveryService;

    private NotificationPushDeliveryEventListener listener;

    @BeforeEach
    void setUp() {
        listener = new NotificationPushDeliveryEventListener(deliveryService);
    }

    @Test
    void deliversPushWhenEventRequestsIt() {
        UUID notificationId = UUID.randomUUID();

        listener.onNotificationCreated(new NotificationCreatedEvent(
                notificationId,
                "user@guidemate.test",
                true
        ));

        verify(deliveryService).deliver(notificationId);
    }

    @Test
    void skipsPushWhenEventDoesNotRequestIt() {
        listener.onNotificationCreated(new NotificationCreatedEvent(
                UUID.randomUUID(),
                "user@guidemate.test",
                false
        ));

        verifyNoInteractions(deliveryService);
    }
}
