package com.ahmetkaragunlu.guidematebackend.notification.service.reminder;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UpcomingTourReminderPolicyTest {

    @Test
    void exposesOnlyBookableAndClosedSessionsToQueryAndLockedRevalidation() {
        assertThat(UpcomingTourReminderPolicy.sessionStatuses())
                .containsExactly(
                        TourSessionStatus.OPEN_FOR_BOOKING,
                        TourSessionStatus.CLOSED
                )
                .allMatch(UpcomingTourReminderPolicy::supports);
        assertThat(TourSessionStatus.values())
                .filteredOn(status -> !UpcomingTourReminderPolicy.sessionStatuses().contains(status))
                .noneMatch(UpcomingTourReminderPolicy::supports);
    }
}
