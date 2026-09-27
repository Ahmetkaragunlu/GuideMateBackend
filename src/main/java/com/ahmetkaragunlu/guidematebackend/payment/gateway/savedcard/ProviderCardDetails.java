package com.ahmetkaragunlu.guidematebackend.payment.gateway.savedcard;

public record ProviderCardDetails(
        // Provider references
        String customerKey,
        String cardToken,

        // Display identity
        String alias,
        String bankName,
        String bankCode,

        // Card classification
        String cardFamily,
        String cardAssociation,
        String cardType,

        // Masked card details
        String lastFourDigits,
        String cardHolderName,
        Integer expiryMonth,
        Integer expiryYear
) {
}
