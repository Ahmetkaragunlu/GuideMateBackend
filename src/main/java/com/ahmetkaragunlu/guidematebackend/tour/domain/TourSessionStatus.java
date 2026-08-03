package com.ahmetkaragunlu.guidematebackend.tour.domain;

public enum TourSessionStatus {
    OPEN_FOR_BOOKING,
    CLOSED,
    COMPLETED,
    CANCELLED;

    public boolean isManageable() {
        return this == OPEN_FOR_BOOKING || this == CLOSED;
    }

    public boolean isTerminal() {
        return this == COMPLETED || this == CANCELLED;
    }
}
