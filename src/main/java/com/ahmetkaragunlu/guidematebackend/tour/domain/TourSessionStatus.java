package com.ahmetkaragunlu.guidematebackend.tour.domain;

public enum TourSessionStatus {
    OPEN_FOR_BOOKING,
    CLOSED,
    COMPLETED,
    CANCELLED,
    EXPIRED;

    public boolean isManageable() {
        return this == OPEN_FOR_BOOKING || this == CLOSED;
    }

    public boolean isTerminal() {
        return this == COMPLETED || this == CANCELLED || this == EXPIRED;
    }
}
