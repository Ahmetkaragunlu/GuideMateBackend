package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.refund;

public record ProviderRefundResult(
        boolean successful,
        String providerRefundId,
        String providerFailureCode
) {
}
