package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

import java.time.Duration;

public record HostedCheckoutSession(
        String token,
        String paymentPageUrl,
        Duration expiresIn
) {
}
