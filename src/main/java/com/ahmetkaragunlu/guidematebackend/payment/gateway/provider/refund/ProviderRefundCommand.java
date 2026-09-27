package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.refund;

public record ProviderRefundCommand(
        String conversationId,
        String providerTransactionId,
        long amountMinor,
        String currencyCode,
        String ipAddress
) {
}
