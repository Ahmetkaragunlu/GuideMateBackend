package com.ahmetkaragunlu.guidematebackend.payment.service.payment;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;

public record HostedPaymentIntent(
        Payment payment,
        boolean initializationRequired
) {
}
