package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

import com.ahmetkaragunlu.guidematebackend.payment.gateway.savedcard.ProviderCardDetails;

public record VerifiedPaymentResult(
        // Verification outcome
        boolean successful,
        String token,
        String conversationId,

        // Provider references
        String providerPaymentId,
        String providerTransactionId,

        // Charged amount
        long amountMinor,
        String currencyCode,

        // Provider result
        String providerStatus,
        String providerFailureCode,
        ProviderCardDetails providerCard
) {
}
