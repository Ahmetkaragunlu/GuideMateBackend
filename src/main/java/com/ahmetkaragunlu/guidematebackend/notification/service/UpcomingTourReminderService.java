package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UpcomingTourReminderService {

    private static final List<TourSessionStatus> REMINDABLE_SESSION_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );

    private final ReservationRepository reservationRepository;
    private final TourSessionRepository sessionRepository;
    private final NotificationPublisher notificationPublisher;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Transactional
    public void remindTourist(UUID reservationId) {
        Reservation reservation = reservationRepository.findByIdForUpdate(reservationId).orElse(null);
        Instant now = clock.instant();
        if (reservation == null
                || reservation.getStatus() != ReservationStatus.CONFIRMED
                || reservation.getUpcomingReminderSentAt() != null
                || !isWithinReminderWindow(reservation.getSession().getStartsAt(), now)) {
            return;
        }
        notificationPublisher.publish(new NotificationCommand(
                reservation.getTourist().getId(),
                NotificationType.UPCOMING_TOUR_REMINDER,
                null,
                Map.of(
                        "reservationId", reservation.getId().toString(),
                        "sessionId", reservation.getSession().getId().toString(),
                        "tourId", reservation.getSession().getTour().getId().toString(),
                        "tourTitle", reservation.getSession().getTour().getTitle(),
                        "startsAt", reservation.getSession().getStartsAt().toString()
                ),
                "tourist-reservation:" + reservation.getId()
        ));
        reservation.markUpcomingReminderSent(now);
    }

    @Transactional
    public void remindGuide(UUID sessionId) {
        TourSession session = sessionRepository.findByIdForUpdate(sessionId).orElse(null);
        Instant now = clock.instant();
        if (session == null
                || session.getTour().getApprovalStatus() != TourApprovalStatus.APPROVED
                || !REMINDABLE_SESSION_STATUSES.contains(session.getStatus())
                || session.getUpcomingReminderSentAt() != null
                || !isWithinReminderWindow(session.getStartsAt(), now)) {
            return;
        }
        notificationPublisher.publish(new NotificationCommand(
                session.getTour().getGuide().getId(),
                NotificationType.UPCOMING_TOUR_REMINDER,
                null,
                Map.of(
                        "sessionId", session.getId().toString(),
                        "tourId", session.getTour().getId().toString(),
                        "tourTitle", session.getTour().getTitle(),
                        "startsAt", session.getStartsAt().toString()
                ),
                "guide-session:" + session.getId()
        ));
        session.markUpcomingReminderSent(now);
    }

    private boolean isWithinReminderWindow(Instant startsAt, Instant now) {
        return startsAt.isAfter(now) && !startsAt.isAfter(now.plus(properties.reminderLeadTime()));
    }
}
