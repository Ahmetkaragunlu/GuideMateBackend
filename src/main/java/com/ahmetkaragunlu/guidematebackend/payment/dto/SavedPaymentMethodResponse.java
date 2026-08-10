package com.ahmetkaragunlu.guidematebackend.payment.dto;

import java.util.UUID;

public record SavedPaymentMethodResponse(
        UUID savedPaymentMethodId,
        String alias,
        String bankName,
        String bankCode,
        String cardFamily,
        String cardAssociation,
        String cardType,
        String lastFourDigits,
        String cardHolderName,
        Integer expiryMonth,
        Integer expiryYear,
        boolean defaultMethod
) {
}
