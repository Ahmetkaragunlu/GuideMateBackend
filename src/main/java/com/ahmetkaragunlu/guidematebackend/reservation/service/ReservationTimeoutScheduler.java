package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
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
public class ReservationTimeoutScheduler {

    private final ReservationRepository reservationRepository;
    private final ReservationTimeoutStateService stateService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.reservation-delay-ms:30000}",
            fixedDelayString = "${scheduler.reservation-delay-ms:30000}"
    )
    public void expireDueHolds() {
        reservationRepository.findExpiredHoldCandidateIds(
                ReservationStatus.PENDING_PAYMENT,
                clock.instant(),
                PageRequest.of(0, properties.batchSize())
        ).forEach(this::expireSafely);
    }

    private void expireSafely(UUID reservationId) {
        try {
            stateService.expireHold(reservationId);
        } catch (RuntimeException exception) {
            log.warn("Reservation hold expiration will retry reservation {}", reservationId);
        }
    }
}
