package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

public record ProviderRefundResult(
        boolean successful,
        String providerRefundId,
        String providerFailureCode
) {
}
