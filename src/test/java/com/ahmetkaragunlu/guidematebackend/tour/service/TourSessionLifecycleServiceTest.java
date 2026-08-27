package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationLifecycleService;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TourSessionLifecycleServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-27T09:00:00Z");

    @Mock
    private TourSessionRepository tourSessionRepository;
    @Mock
    private ReservationLifecycleService reservationLifecycleService;
    @Mock
    private NotificationPublisher notificationPublisher;

    private TourSessionLifecycleService service;

    @BeforeEach
    void setUp() {
        service = new TourSessionLifecycleService(
                tourSessionRepository,
                reservationLifecycleService,
                notificationPublisher,
                TestSchedulerProperties.defaults(),
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void completesOnlyEndedSessionsAndPublishesCanonicalNotification() {
        UUID sessionId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        TourSession ended = org.mockito.Mockito.mock(TourSession.class);
        TourSession stillRunning = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        User guide = org.mockito.Mockito.mock(User.class);
        when(tourSessionRepository.findByStatusInAndStartsAtBeforeOrderByStartsAtAsc(
                anyCollection(),
                org.mockito.ArgumentMatchers.eq(NOW),
                org.mockito.ArgumentMatchers.eq(PageRequest.of(0, 25))
        )).thenReturn(List.of(ended, stillRunning));
        when(ended.endsAt()).thenReturn(NOW);
        when(ended.getId()).thenReturn(sessionId);
        when(ended.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);
        when(tour.getTitle()).thenReturn("Completed tour");
        when(tour.getGuide()).thenReturn(guide);
        when(guide.getId()).thenReturn(7L);
        when(stillRunning.endsAt()).thenReturn(NOW.plusSeconds(1));

        service.completeFinishedSessions();

        verify(ended).complete();
        verify(reservationLifecycleService).completeForSession(sessionId);
        verify(stillRunning, never()).complete();
        ArgumentCaptor<NotificationCommand> notificationCaptor =
                ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(notificationCaptor.capture());
        assertThat(notificationCaptor.getValue().type()).isEqualTo(NotificationType.TOUR_COMPLETED);
        assertThat(notificationCaptor.getValue().payload())
                .containsEntry("sessionId", sessionId.toString())
                .containsEntry("tourId", tourId.toString())
                .containsEntry("tourTitle", "Completed tour");
    }
}
