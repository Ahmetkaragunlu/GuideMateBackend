package com.ahmetkaragunlu.guidematebackend.notification.domain;

public enum NotificationType {

    // Tour moderation
    TOUR_APPROVED,
    TOUR_REJECTED,
    TOUR_CHANGE_APPROVED,
    TOUR_CHANGE_REJECTED,

    // Reservations and tour lifecycle
    TOUR_PURCHASED,
    RESERVATION_CONFIRMED,
    RESERVATION_CANCELLED,
    TOUR_CANCELLED,
    TOUR_COMPLETED,

    // Reviews
    REVIEW_REQUEST,
    RATING_RECEIVED,
    COMMENT_RECEIVED,

    // Payments and earnings
    PAYMENT_SUCCEEDED,
    PAYMENT_FAILED,
    REFUND_REQUESTED,
    REFUND_COMPLETED,
    REFUND_FAILED,
    REFUND_MANUAL_REVIEW,
    EARNING_AVAILABLE,
    WITHDRAWAL_COMPLETED,

    // Communication
    CHAT_MESSAGE,

    // Reminders
    UPCOMING_TOUR_REMINDER,

    // Security
    SECURITY_ALERT
}
