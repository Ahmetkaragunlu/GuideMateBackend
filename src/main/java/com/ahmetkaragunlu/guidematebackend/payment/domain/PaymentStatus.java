package com.ahmetkaragunlu.guidematebackend.payment.domain;

public enum PaymentStatus {
    PENDING,
    REQUIRES_ACTION,
    VERIFYING,
    SUCCEEDED,
    FAILED,
    CANCELLED,
    TIMEOUT;

    public boolean isTerminal() {
        return this == SUCCEEDED || this == FAILED || this == CANCELLED || this == TIMEOUT;
    }
}
