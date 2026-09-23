package com.ahmetkaragunlu.guidematebackend.notification.service.delivery;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPayloadCodec;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPreferenceService;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationPushDeliveryStateServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private NotificationRepository notificationRepository;
    @Mock private DeviceRegistrationRepository registrationRepository;
    @Mock private NotificationPreferenceService preferenceService;
    @Mock private NotificationPayloadCodec payloadCodec;

    private NotificationPushDeliveryStateService service;

    @BeforeEach
    void setUp() {
        service = new NotificationPushDeliveryStateService(
                notificationRepository,
                registrationRepository,
                preferenceService,
                payloadCodec,
                TestSchedulerProperties.defaults(),
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void marksPushNotRequestedWhenPreferenceIsDisabled() {
        UUID notificationId = UUID.randomUUID();
        Notification notification = pendingNotification(42L);
        when(notificationRepository.findByIdForUpdate(notificationId)).thenReturn(Optional.of(notification));
        when(preferenceService.isPushEnabled(42L, NotificationType.SECURITY_ALERT)).thenReturn(false);

        assertThat(service.begin(notificationId, true)).isNull();
        verify(notification).markPushNotRequested();
        verify(registrationRepository, never()).findAllByUser_IdAndActiveTrue(42L);
    }

    @Test
    void createsWhitelistedPushAttemptForActiveTargets() {
        UUID notificationId = UUID.randomUUID();
        UUID registrationId = UUID.randomUUID();
        Notification notification = pendingNotification(42L);
        when(notification.getId()).thenReturn(notificationId);
        when(notification.getPayloadJson()).thenReturn("payload");
        DeviceRegistration registration = org.mockito.Mockito.mock(DeviceRegistration.class);
        when(registration.getId()).thenReturn(registrationId);
        when(registration.getFirebaseInstallationId()).thenReturn("firebase-id");
        when(notificationRepository.findByIdForUpdate(notificationId)).thenReturn(Optional.of(notification));
        when(preferenceService.isPushEnabled(42L, NotificationType.SECURITY_ALERT)).thenReturn(true);
        when(registrationRepository.findAllByUser_IdAndActiveTrue(42L)).thenReturn(List.of(registration));
        when(payloadCodec.decode("payload")).thenReturn(Map.of(
                "securityEvent", "PASSWORD_CHANGED",
                "privateText", "must-not-leak"
        ));

        var attempt = service.begin(notificationId, true);

        assertThat(attempt.targets()).containsExactly(
                new NotificationPushDeliveryStateService.PushTarget(registrationId, "firebase-id")
        );
        assertThat(attempt.data()).containsEntry("recipientUserId", "42")
                .containsEntry("securityEvent", "PASSWORD_CHANGED")
                .doesNotContainKey("privateText");
    }

    @Test
    void deactivatesInvalidRegistrationAndMarksDeliveryFailed() {
        UUID notificationId = UUID.randomUUID();
        UUID registrationId = UUID.randomUUID();
        DeviceRegistration registration = org.mockito.Mockito.mock(DeviceRegistration.class);
        Notification notification = org.mockito.Mockito.mock(Notification.class);
        when(notification.getPushStatus()).thenReturn(NotificationPushStatus.PENDING);
        when(registrationRepository.findAllById(Set.of(registrationId))).thenReturn(List.of(registration));
        when(notificationRepository.findByIdForUpdate(notificationId)).thenReturn(Optional.of(notification));

        service.complete(notificationId, Set.of(registrationId), false);

        verify(registration).deactivate();
        verify(notification).markPushFailed();
    }

    private Notification pendingNotification(Long recipientId) {
        Notification notification = org.mockito.Mockito.mock(Notification.class);
        User recipient = org.mockito.Mockito.mock(User.class);
        when(notification.getRecipient()).thenReturn(recipient);
        when(recipient.getId()).thenReturn(recipientId);
        when(notification.getType()).thenReturn(NotificationType.SECURITY_ALERT);
        when(notification.getPushStatus()).thenReturn(NotificationPushStatus.PENDING);
        when(notification.canAttemptPush(NOW, TestSchedulerProperties.defaults().notificationMaxAttempts()))
                .thenReturn(true);
        return notification;
    }
}
