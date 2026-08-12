package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class NotificationRetryScheduler {

    private static final List<NotificationPushStatus> RETRYABLE_STATUSES = List.of(
            NotificationPushStatus.PENDING,
            NotificationPushStatus.FAILED
    );

    private final NotificationRepository notificationRepository;
    private final NotificationPushDeliveryService deliveryService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.notification-delay-ms:60000}",
            fixedDelayString = "${scheduler.notification-delay-ms:60000}"
    )
    public void retryPushDeliveries() {
        notificationRepository.findPushRetryCandidateIds(
                RETRYABLE_STATUSES,
                clock.instant(),
                properties.notificationMaxAttempts(),
                PageRequest.of(0, properties.batchSize())
        ).forEach(this::deliverSafely);
    }

    private void deliverSafely(UUID notificationId) {
        try {
            deliveryService.deliver(notificationId);
        } catch (RuntimeException exception) {
            log.warn("Push delivery will retry notification {}", notificationId);
        }
    }
}
