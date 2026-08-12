package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class UpcomingTourReminderScheduler {

    private static final List<TourSessionStatus> REMINDABLE_SESSION_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );

    private final ReservationRepository reservationRepository;
    private final TourSessionRepository sessionRepository;
    private final UpcomingTourReminderService reminderService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.reminder-delay-ms:300000}",
            fixedDelayString = "${scheduler.reminder-delay-ms:300000}"
    )
    public void createUpcomingTourReminders() {
        Instant now = clock.instant();
        Instant until = now.plus(properties.reminderLeadTime());
        PageRequest batch = PageRequest.of(0, properties.batchSize());

        reservationRepository.findUpcomingReminderCandidateIds(
                ReservationStatus.CONFIRMED,
                now,
                until,
                batch
        ).forEach(this::remindTouristSafely);

        sessionRepository.findUpcomingReminderCandidateIds(
                TourApprovalStatus.APPROVED,
                REMINDABLE_SESSION_STATUSES,
                now,
                until,
                batch
        ).forEach(this::remindGuideSafely);
    }

    private void remindTouristSafely(UUID reservationId) {
        try {
            reminderService.remindTourist(reservationId);
        } catch (RuntimeException exception) {
            log.warn("Tourist reminder will retry reservation {}", reservationId);
        }
    }

    private void remindGuideSafely(UUID sessionId) {
        try {
            reminderService.remindGuide(sessionId);
        } catch (RuntimeException exception) {
            log.warn("Guide reminder will retry session {}", sessionId);
        }
    }
}
