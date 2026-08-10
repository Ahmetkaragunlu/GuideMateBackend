package com.ahmetkaragunlu.guidematebackend.payment.service;

import java.util.UUID;

public record SavedCardDeletion(
        UUID savedPaymentMethodId,
        String customerKey,
        String cardToken
) {
}
