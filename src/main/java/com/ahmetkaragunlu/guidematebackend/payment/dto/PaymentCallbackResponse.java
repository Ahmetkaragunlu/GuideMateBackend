package com.ahmetkaragunlu.guidematebackend.payment.dto;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;

import java.util.UUID;

public record PaymentCallbackResponse(
        UUID paymentId,
        PaymentStatus paymentStatus
) {
}
