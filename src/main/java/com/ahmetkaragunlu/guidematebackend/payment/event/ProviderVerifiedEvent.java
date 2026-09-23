package com.ahmetkaragunlu.guidematebackend.payment.event;

public record ProviderVerifiedEvent(
        String eventType,
        String providerEventId,
        String payloadHash
) {
}
