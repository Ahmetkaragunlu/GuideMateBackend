package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;

public record HostedPaymentIntent(
        Payment payment,
        boolean initializationRequired
) {
}
