package com.ahmetkaragunlu.guidematebackend.notification.service.device;

import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceRegistrationCleanupSchedulerTest {

    @Mock private DeviceRegistrationRepository repository;
    @Mock private DeviceRegistrationService service;

    @Test
    void continuesCleanupAfterOneCandidateFails() {
        Instant now = Instant.parse("2026-09-24T12:00:00Z");
        var properties = TestSchedulerProperties.defaults();
        UUID failing = UUID.randomUUID();
        UUID next = UUID.randomUUID();
        UUID expired = UUID.randomUUID();
        when(repository.findCleanupCandidateIds(eq(true), any(), any(Pageable.class)))
                .thenReturn(List.of(failing, next));
        when(repository.findCleanupCandidateIds(eq(false), any(), any(Pageable.class)))
                .thenReturn(List.of(expired));
        doThrow(new IllegalStateException("locked"))
                .when(service).deactivateIfInactive(failing, now.minus(properties.deviceInactiveAfter()));
        DeviceRegistrationCleanupScheduler scheduler = new DeviceRegistrationCleanupScheduler(
                repository,
                service,
                properties,
                Clock.fixed(now, ZoneOffset.UTC)
        );

        scheduler.cleanupInactiveRegistrations();

        verify(service).deactivateIfInactive(next, now.minus(properties.deviceInactiveAfter()));
        verify(service).deleteIfExpired(expired, now.minus(properties.deviceDeleteAfter()));
    }
}
