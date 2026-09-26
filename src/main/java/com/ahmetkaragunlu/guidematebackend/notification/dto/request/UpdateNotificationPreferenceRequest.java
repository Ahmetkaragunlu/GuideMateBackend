package com.ahmetkaragunlu.guidematebackend.notification.dto.request;

public record UpdateNotificationPreferenceRequest(
        Boolean upcomingTourRemindersEnabled,
        Boolean chatMessagesEnabled,
        Boolean reservationUpdatesEnabled,
        Boolean reviewRequestsEnabled,
        Boolean paymentsAndEarningsEnabled,
        Boolean newReviewsEnabled
) {
}
