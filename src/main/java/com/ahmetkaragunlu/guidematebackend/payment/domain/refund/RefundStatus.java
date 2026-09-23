package com.ahmetkaragunlu.guidematebackend.payment.domain.refund;

public enum RefundStatus {
    REQUESTED,
    PROCESSING,
    SUCCEEDED,
    FAILED,
    MANUAL_REVIEW
}
