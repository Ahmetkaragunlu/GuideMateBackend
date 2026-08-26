package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
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

class ReservationTimeoutSchedulerTest {

    @Test
    void continuesExpiringBatchAfterOneReservationFails() {
        Instant now = Instant.parse("2026-08-27T10:00:00Z");
        SchedulerProperties properties = TestSchedulerProperties.defaults();
        ReservationRepository repository = mock(ReservationRepository.class);
        ReservationTimeoutStateService stateService = mock(ReservationTimeoutStateService.class);
        ReservationTimeoutScheduler scheduler = new ReservationTimeoutScheduler(
                repository,
                stateService,
                properties,
                Clock.fixed(now, ZoneOffset.UTC)
        );
        UUID failed = UUID.randomUUID();
        UUID successful = UUID.randomUUID();
        when(repository.findExpiredHoldCandidateIds(
                ReservationStatus.PENDING_PAYMENT,
                now,
                PageRequest.of(0, properties.batchSize())
        )).thenReturn(List.of(failed, successful));
        doThrow(new IllegalStateException("concurrent update"))
                .when(stateService)
                .expireHold(failed);

        scheduler.expireDueHolds();

        verify(stateService).expireHold(failed);
        verify(stateService).expireHold(successful);
    }
}
