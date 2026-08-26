package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NotificationRetrySchedulerTest {

    @Test
    void continuesPushBatchAfterOneDeliveryFails() {
        Instant now = Instant.parse("2026-08-27T10:00:00Z");
        SchedulerProperties properties = TestSchedulerProperties.defaults();
        NotificationRepository repository = mock(NotificationRepository.class);
        NotificationPushDeliveryService deliveryService = mock(NotificationPushDeliveryService.class);
        NotificationRetryScheduler scheduler = new NotificationRetryScheduler(
                repository,
                deliveryService,
                properties,
                Clock.fixed(now, ZoneOffset.UTC)
        );
        UUID failed = UUID.randomUUID();
        UUID successful = UUID.randomUUID();
        when(repository.findPushRetryCandidateIds(
                List.of(NotificationPushStatus.PENDING, NotificationPushStatus.FAILED),
                now,
                properties.notificationMaxAttempts(),
                PageRequest.of(0, properties.batchSize())
        )).thenReturn(List.of(failed, successful));
        doThrow(new IllegalStateException("FCM unavailable"))
                .when(deliveryService)
                .deliver(failed);

        scheduler.retryPushDeliveries();

        verify(deliveryService).deliver(failed);
        verify(deliveryService).deliver(successful);
    }
}
