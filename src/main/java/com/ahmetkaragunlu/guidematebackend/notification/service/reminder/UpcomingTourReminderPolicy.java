package com.ahmetkaragunlu.guidematebackend.notification.service.reminder;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;

import java.util.List;

final class UpcomingTourReminderPolicy {

    private static final List<TourSessionStatus> SESSION_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );

    private UpcomingTourReminderPolicy() {
    }

    static List<TourSessionStatus> sessionStatuses() {
        return SESSION_STATUSES;
    }

    static boolean supports(TourSessionStatus status) {
        return SESSION_STATUSES.contains(status);
    }
}
