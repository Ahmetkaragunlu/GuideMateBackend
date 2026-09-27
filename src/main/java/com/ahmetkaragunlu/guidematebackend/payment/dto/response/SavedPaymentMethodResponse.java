package com.ahmetkaragunlu.guidematebackend.payment.dto.response;

import java.util.UUID;

public record SavedPaymentMethodResponse(
        // Saved method identity
        UUID savedPaymentMethodId,
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
