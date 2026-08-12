package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class DeviceRegistrationCleanupScheduler {

    private final DeviceRegistrationRepository registrationRepository;
    private final DeviceRegistrationService registrationService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.device-cleanup-delay-ms:3600000}",
            fixedDelayString = "${scheduler.device-cleanup-delay-ms:3600000}"
    )
    public void cleanupInactiveRegistrations() {
        Instant now = clock.instant();
        PageRequest batch = PageRequest.of(0, properties.batchSize());
        Instant inactiveBefore = now.minus(properties.deviceInactiveAfter());
        Instant deleteBefore = now.minus(properties.deviceDeleteAfter());

        registrationRepository.findCleanupCandidateIds(true, inactiveBefore, batch)
                .forEach(id -> deactivateSafely(id, inactiveBefore));
        registrationRepository.findCleanupCandidateIds(false, deleteBefore, batch)
                .forEach(id -> deleteSafely(id, deleteBefore));
    }

    private void deactivateSafely(UUID registrationId, Instant cutoff) {
        try {
            registrationService.deactivateIfInactive(registrationId, cutoff);
        } catch (RuntimeException exception) {
            log.warn("Device registration cleanup will retry registration {}", registrationId);
        }
    }

    private void deleteSafely(UUID registrationId, Instant cutoff) {
        try {
            registrationService.deleteIfExpired(registrationId, cutoff);
        } catch (RuntimeException exception) {
            log.warn("Device registration deletion will retry registration {}", registrationId);
        }
    }
}
