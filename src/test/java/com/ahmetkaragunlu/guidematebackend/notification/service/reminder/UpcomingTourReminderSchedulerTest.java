package com.ahmetkaragunlu.guidematebackend.notification.service.reminder;

import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
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
class UpcomingTourReminderSchedulerTest {

    @Mock private ReservationRepository reservationRepository;
    @Mock private TourSessionRepository sessionRepository;
    @Mock private UpcomingTourReminderService reminderService;

    @Test
    void isolatesTouristAndGuideReminderFailures() {
        UUID failingReservation = UUID.randomUUID();
        UUID nextReservation = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        when(reservationRepository.findUpcomingReminderCandidateIds(any(), any(), any(), any()))
                .thenReturn(List.of(failingReservation, nextReservation));
        when(sessionRepository.findUpcomingReminderCandidateIds(any(), any(), any(), any(), any()))
                .thenReturn(List.of(sessionId));
        doThrow(new IllegalStateException("temporary"))
                .when(reminderService).remindTourist(failingReservation);
        UpcomingTourReminderScheduler scheduler = new UpcomingTourReminderScheduler(
                reservationRepository,
                sessionRepository,
                reminderService,
                TestSchedulerProperties.defaults(),
                Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"), ZoneOffset.UTC)
        );

        scheduler.createUpcomingTourReminders();

        verify(reminderService).remindTourist(nextReservation);
        verify(reminderService).remindGuide(sessionId);
    }
}
