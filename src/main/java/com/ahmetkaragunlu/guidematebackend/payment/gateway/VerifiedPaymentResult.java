package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public record VerifiedPaymentResult(
        boolean successful,
        String token,
        String conversationId,
        String providerPaymentId,
        String providerTransactionId,
        long amountMinor,
        String currencyCode,
        String providerStatus,
        String providerFailureCode
) {
}
