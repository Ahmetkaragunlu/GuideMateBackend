package com.ahmetkaragunlu.guidematebackend.payment.domain;

public record SavedCardMetadata(
        String alias,
        String bankName,
        String bankCode,
        String cardFamily,
        String cardAssociation,
        String cardType,
        String lastFourDigits,
        String cardHolderName,
        Short expiryMonth,
        Short expiryYear
) {
}
