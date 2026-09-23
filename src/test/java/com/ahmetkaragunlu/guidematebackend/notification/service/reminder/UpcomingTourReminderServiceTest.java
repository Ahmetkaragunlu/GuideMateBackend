package com.ahmetkaragunlu.guidematebackend.notification.service.reminder;

import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UpcomingTourReminderServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private ReservationRepository reservationRepository;
    @Mock private TourSessionRepository sessionRepository;
    @Mock private NotificationPublisher notificationPublisher;

    private UpcomingTourReminderService service;

    @BeforeEach
    void setUp() {
        service = new UpcomingTourReminderService(
                reservationRepository,
                sessionRepository,
                notificationPublisher,
                TestSchedulerProperties.defaults(),
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void publishesTouristReminderOnceInsideConfiguredWindow() {
        UUID reservationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        User tourist = org.mockito.Mockito.mock(User.class);
        when(reservation.getStatus()).thenReturn(ReservationStatus.CONFIRMED);
        when(reservation.getUpcomingReminderSentAt()).thenReturn(null);
        when(reservation.getSession()).thenReturn(session);
        when(reservation.getTourist()).thenReturn(tourist);
        when(reservation.getId()).thenReturn(reservationId);
        when(tourist.getId()).thenReturn(42L);
        when(session.getId()).thenReturn(sessionId);
        when(session.getStartsAt()).thenReturn(NOW.plusSeconds(3600));
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);
        when(tour.getTitle()).thenReturn("İstanbul Tarih Turu");
        when(reservationRepository.findByIdForUpdate(reservationId)).thenReturn(Optional.of(reservation));

        service.remindTourist(reservationId);

        ArgumentCaptor<NotificationCommand> command = ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(command.capture());
        assertThat(command.getValue().recipientId()).isEqualTo(42L);
        assertThat(command.getValue().payload()).containsEntry("reservationId", reservationId.toString());
        verify(reservation).markUpcomingReminderSent(NOW);
    }

    @Test
    void skipsReservationThatWasAlreadyReminded() {
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        when(reservation.getStatus()).thenReturn(ReservationStatus.CONFIRMED);
        when(reservation.getUpcomingReminderSentAt()).thenReturn(NOW.minusSeconds(60));
        when(reservationRepository.findByIdForUpdate(reservationId)).thenReturn(Optional.of(reservation));

        service.remindTourist(reservationId);

        verify(notificationPublisher, never()).publish(org.mockito.ArgumentMatchers.any());
        verify(reservation, never()).markUpcomingReminderSent(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void publishesGuideReminderOnlyForApprovedSupportedSession() {
        UUID sessionId = UUID.randomUUID();
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        User guide = org.mockito.Mockito.mock(User.class);
        when(session.getStatus()).thenReturn(TourSessionStatus.OPEN_FOR_BOOKING);
        when(session.getUpcomingReminderSentAt()).thenReturn(null);
        when(session.getStartsAt()).thenReturn(NOW.plusSeconds(3600));
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(tour.getApprovalStatus()).thenReturn(TourApprovalStatus.APPROVED);
        when(tour.getGuide()).thenReturn(guide);
        when(tour.getId()).thenReturn(UUID.randomUUID());
        when(tour.getTitle()).thenReturn("Kapadokya Turu");
        when(guide.getId()).thenReturn(7L);
        when(sessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        service.remindGuide(sessionId);

        ArgumentCaptor<NotificationCommand> command = ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(command.capture());
        assertThat(command.getValue().recipientId()).isEqualTo(7L);
        verify(session).markUpcomingReminderSent(NOW);
    }
}
