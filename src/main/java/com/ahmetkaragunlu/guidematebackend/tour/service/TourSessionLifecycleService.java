package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationLifecycleService;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TourSessionLifecycleService {

    private static final List<TourSessionStatus> COMPLETION_CANDIDATE_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );

    private final TourSessionRepository tourSessionRepository;
    private final ReservationLifecycleService reservationLifecycleService;
    private final NotificationPublisher notificationPublisher;
    private final SchedulerProperties schedulerProperties;
    private final Clock clock;

    @Scheduled(fixedDelayString = "${tour.lifecycle-delay-ms:60000}")
    @Transactional
    public void completeFinishedSessions() {
        Instant now = clock.instant();
        tourSessionRepository.findByStatusInAndStartsAtBeforeOrderByStartsAtAsc(
                        COMPLETION_CANDIDATE_STATUSES,
                        now,
                        PageRequest.of(0, schedulerProperties.batchSize())
                )
                .stream()
                .filter(session -> !session.endsAt().isAfter(now))
                .forEach(session -> {
                    session.complete();
                    reservationLifecycleService.completeForSession(session.getId());
                    notificationPublisher.publish(new NotificationCommand(
                            session.getTour().getGuide().getId(),
                            NotificationType.TOUR_COMPLETED,
                            null,
                            Map.of(
                                    "sessionId", session.getId().toString(),
                                    "tourId", session.getTour().getId().toString(),
                                    "tourTitle", session.getTour().getTitle()
                            )
                    ));
                });
    }
}
