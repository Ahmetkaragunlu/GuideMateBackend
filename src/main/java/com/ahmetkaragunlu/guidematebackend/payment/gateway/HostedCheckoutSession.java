package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import java.time.Duration;

public record HostedCheckoutSession(
        String token,
        String paymentPageUrl,
        Duration expiresIn
) {
}
