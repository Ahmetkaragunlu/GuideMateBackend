package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.event.NotificationCreatedEvent;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationServiceTest {

    @Mock
    private NotificationRepository notificationRepository;
    @Mock
    private NotificationPreferenceService preferenceService;
    @Mock
    private NotificationPayloadCodec payloadCodec;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Test
    void returnsExistingDeduplicatedNotificationWithoutPublishingAnotherEvent() {
        Long recipientId = 42L;
        String deduplicationKey = "reservation:" + UUID.randomUUID();
        UUID existingId = UUID.randomUUID();
        User recipient = mock(User.class);
        Notification existing = mock(Notification.class);
        when(userRepository.findByIdForUpdate(recipientId)).thenReturn(Optional.of(recipient));
        when(notificationRepository.findByRecipient_IdAndTypeAndDeduplicationKey(
                recipientId,
                NotificationType.RESERVATION_CONFIRMED,
                deduplicationKey
        )).thenReturn(Optional.of(existing));
        when(existing.getId()).thenReturn(existingId);
        NotificationService service = new NotificationService(
                notificationRepository,
                preferenceService,
                payloadCodec,
                userRepository,
                eventPublisher,
                Clock.systemUTC()
        );

        UUID result = service.publish(new NotificationCommand(
                recipientId,
                NotificationType.RESERVATION_CONFIRMED,
                null,
                Map.of("reservationId", UUID.randomUUID().toString()),
                deduplicationKey
        ));

        assertThat(result).isEqualTo(existingId);
        verify(notificationRepository, never()).save(org.mockito.ArgumentMatchers.any());
        verifyNoInteractions(preferenceService, payloadCodec, eventPublisher);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void publishesNotificationEventWithPushDecisionFromUserPreference(boolean pushEnabled) {
        Long recipientId = 42L;
        UUID notificationId = UUID.randomUUID();
        User recipient = mock(User.class);
        Notification savedNotification = mock(Notification.class);
        when(userRepository.getReferenceById(recipientId)).thenReturn(recipient);
        when(recipient.getUsername()).thenReturn("user@guidemate.test");
        when(preferenceService.isPushEnabled(recipientId, NotificationType.CHAT_MESSAGE))
                .thenReturn(pushEnabled);
        when(payloadCodec.encode(Map.of("chatId", "chat-1"))).thenReturn("{\"chatId\":\"chat-1\"}");
        when(notificationRepository.save(org.mockito.ArgumentMatchers.any(Notification.class)))
                .thenReturn(savedNotification);
        when(savedNotification.getId()).thenReturn(notificationId);
        NotificationService service = new NotificationService(
                notificationRepository,
                preferenceService,
                payloadCodec,
                userRepository,
                eventPublisher,
                Clock.systemUTC()
        );

        UUID result = service.publish(new NotificationCommand(
                recipientId,
                NotificationType.CHAT_MESSAGE,
                null,
                Map.of("chatId", "chat-1")
        ));

        assertThat(result).isEqualTo(notificationId);
        verify(eventPublisher).publishEvent(new NotificationCreatedEvent(
                notificationId,
                "user@guidemate.test",
                pushEnabled
        ));
    }
}
