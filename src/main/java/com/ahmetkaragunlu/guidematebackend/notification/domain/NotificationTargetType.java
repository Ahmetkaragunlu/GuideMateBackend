package com.ahmetkaragunlu.guidematebackend.notification.domain;

public enum NotificationTargetType {
    CHAT("chatId"),
    TOUR("tourId"),
    RESERVATION("reservationId"),
    PAYMENT("paymentId");

    private final String payloadKey;

    NotificationTargetType(String payloadKey) {
        this.payloadKey = payloadKey;
    }

    public String payloadKey() {
        return payloadKey;
    }
}
