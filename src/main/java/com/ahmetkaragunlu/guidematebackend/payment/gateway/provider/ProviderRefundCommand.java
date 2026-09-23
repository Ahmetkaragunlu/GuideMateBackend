package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

public record ProviderRefundCommand(
        String conversationId,
        String providerTransactionId,
        long amountMinor,
        String currencyCode,
        String ipAddress
) {
}
