package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public record ProviderCardDetails(
        String customerKey,
        String cardToken,
        String alias,
        String bankName,
        String bankCode,
        String cardFamily,
        String cardAssociation,
        String cardType,
        String lastFourDigits,
        String cardHolderName,
        Integer expiryMonth,
        Integer expiryYear
) {
}
