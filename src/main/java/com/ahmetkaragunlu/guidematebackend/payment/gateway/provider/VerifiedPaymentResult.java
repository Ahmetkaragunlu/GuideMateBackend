package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

import com.ahmetkaragunlu.guidematebackend.payment.gateway.savedcard.ProviderCardDetails;

public record VerifiedPaymentResult(
        boolean successful,
        String token,
        String conversationId,
        String providerPaymentId,
        String providerTransactionId,
        long amountMinor,
        String currencyCode,
        String providerStatus,
        String providerFailureCode,
        ProviderCardDetails providerCard
) {
}
