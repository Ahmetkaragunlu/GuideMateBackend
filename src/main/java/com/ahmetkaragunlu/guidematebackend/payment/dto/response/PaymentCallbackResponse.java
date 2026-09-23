package com.ahmetkaragunlu.guidematebackend.payment.dto.response;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;

import java.util.UUID;

public record PaymentCallbackResponse(
        UUID paymentId,
        PaymentStatus paymentStatus
) {
}
