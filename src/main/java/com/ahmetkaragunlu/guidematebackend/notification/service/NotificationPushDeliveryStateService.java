package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class NotificationPushDeliveryStateService {

    private static final Set<String> PUSH_PAYLOAD_KEYS = Set.of("securityEvent");

    private final NotificationRepository notificationRepository;
    private final DeviceRegistrationRepository registrationRepository;
    private final NotificationPayloadCodec payloadCodec;
    private final SchedulerProperties schedulerProperties;
    private final Clock clock;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public PushAttempt begin(UUID notificationId, boolean pushAvailable) {
        Notification notification = notificationRepository.findByIdForUpdate(notificationId).orElse(null);
        Instant now = clock.instant();
        if (notification == null
                || notification.getPushStatus() == NotificationPushStatus.SENT
                || notification.getPushStatus() == NotificationPushStatus.NOT_REQUESTED
                || !notification.canAttemptPush(now, schedulerProperties.notificationMaxAttempts())) {
            return null;
        }
        notification.markPushAttempt(now, now.plus(schedulerProperties.notificationRetryDelay()));
        if (!pushAvailable) {
            notification.markPushNotRequested();
            return null;
        }

        List<PushTarget> targets = registrationRepository.findAllByUser_IdAndActiveTrue(
                        notification.getRecipient().getId()
                ).stream()
                .map(registration -> new PushTarget(
                        registration.getId(),
                        registration.getFirebaseInstallationId()
                ))
                .toList();
        if (targets.isEmpty()) {
            notification.markPushNotRequested();
            return null;
        }
        return new PushAttempt(notification.getId(), pushData(notification), targets);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void complete(UUID notificationId, Set<UUID> invalidRegistrationIds, boolean delivered) {
        if (!invalidRegistrationIds.isEmpty()) {
            registrationRepository.findAllById(invalidRegistrationIds)
                    .forEach(DeviceRegistration::deactivate);
        }
        notificationRepository.findByIdForUpdate(notificationId).ifPresent(notification -> {
            if (notification.getPushStatus() == NotificationPushStatus.SENT
                    || notification.getPushStatus() == NotificationPushStatus.NOT_REQUESTED) {
                return;
            }
            if (delivered) {
                notification.markPushSent();
            } else {
                notification.markPushFailed();
            }
        });
    }

    private Map<String, String> pushData(Notification notification) {
        Map<String, String> data = new HashMap<>();
        data.put("notificationId", notification.getId().toString());
        data.put("type", notification.getType().name());
        payloadCodec.decode(notification.getPayloadJson())
                .forEach((key, value) -> {
                    if (value != null && (key.endsWith("Id") || PUSH_PAYLOAD_KEYS.contains(key))) {
                        data.put(key, String.valueOf(value));
                    }
                });
        return Map.copyOf(data);
    }

    public record PushAttempt(
            UUID notificationId,
            Map<String, String> data,
            List<PushTarget> targets
    ) {
    }

    public record PushTarget(UUID registrationId, String firebaseInstallationId) {
    }
}
