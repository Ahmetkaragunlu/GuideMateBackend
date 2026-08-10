package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public record ProviderRefundResult(
        boolean successful,
        String providerRefundId,
        String providerFailureCode
) {
}
