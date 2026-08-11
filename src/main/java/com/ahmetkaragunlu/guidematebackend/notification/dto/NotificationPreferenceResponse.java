package com.ahmetkaragunlu.guidematebackend.notification.dto;

public record NotificationPreferenceResponse(
        boolean upcomingTourRemindersEnabled,
        boolean chatMessagesEnabled,
        boolean reservationUpdatesEnabled,
        boolean reviewRequestsEnabled,
        boolean paymentsAndEarningsEnabled,
        boolean newReviewsEnabled,
        boolean securityAlertsEnabled
) {
}
