package com.ahmetkaragunlu.guidematebackend.payment.domain.savedcard;

public record SavedCardMetadata(
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
        Short expiryMonth,
        Short expiryYear
) {
}
