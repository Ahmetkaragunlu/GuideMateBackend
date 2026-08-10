package com.ahmetkaragunlu.guidematebackend.payment.service;

public record ProviderVerifiedEvent(
        String eventType,
        String providerEventId,
        String payloadHash
) {
}
