package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

import com.ahmetkaragunlu.guidematebackend.payment.domain.checkout.CheckoutLocale;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.buyer.BuyerProfile;

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
