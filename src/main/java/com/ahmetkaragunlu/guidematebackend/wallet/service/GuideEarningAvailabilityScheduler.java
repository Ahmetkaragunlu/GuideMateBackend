package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class GuideEarningAvailabilityScheduler {

    private final GuideEarningRepository earningRepository;
    private final GuideEarningService earningService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.earning-delay-ms:60000}",
            fixedDelayString = "${scheduler.earning-delay-ms:60000}"
    )
    public void makeDueEarningsAvailable() {
        earningRepository.findAvailabilityCandidateIds(
                GuideEarningStatus.PENDING,
                clock.instant(),
                PageRequest.of(0, properties.batchSize())
        ).forEach(this::makeAvailableSafely);
    }

    private void makeAvailableSafely(UUID earningId) {
        try {
            earningService.makeAvailableById(earningId);
        } catch (RuntimeException exception) {
            log.warn("Guide earning availability will retry earning {}", earningId);
        }
    }
}
