package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import com.ahmetkaragunlu.guidematebackend.payment.domain.CheckoutLocale;

import java.util.UUID;

public record HostedCheckoutCommand(
        UUID paymentId,
        String conversationId,
        long amountMinor,
        String currencyCode,
        CheckoutLocale locale,
        String itemName,
        BuyerProfile buyer,
        String providerCustomerKey
) {
}
