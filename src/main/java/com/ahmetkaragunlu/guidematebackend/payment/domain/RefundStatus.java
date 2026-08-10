package com.ahmetkaragunlu.guidematebackend.payment.domain;

public enum RefundStatus {
    REQUESTED,
    PROCESSING,
    SUCCEEDED,
    FAILED,
    MANUAL_REVIEW
}
