package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideEarningAvailabilitySchedulerTest {

    @Mock private GuideEarningRepository repository;
    @Mock private GuideEarningService service;

    @Test
    void continuesWithRemainingEarningsAfterOneFailure() {
        UUID failing = UUID.randomUUID();
        UUID next = UUID.randomUUID();
        when(repository.findAvailabilityCandidateIds(any(), any(), any()))
                .thenReturn(List.of(failing, next));
        doThrow(new IllegalStateException("locked")).when(service).makeAvailableById(failing);
        GuideEarningAvailabilityScheduler scheduler = new GuideEarningAvailabilityScheduler(
                repository,
                service,
                TestSchedulerProperties.defaults(),
                Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"), ZoneOffset.UTC)
        );

        scheduler.makeDueEarningsAvailable();

        verify(service).makeAvailableById(next);
    }
}
