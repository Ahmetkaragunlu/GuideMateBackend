package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.checkout;

import com.ahmetkaragunlu.guidematebackend.payment.domain.checkout.CheckoutLocale;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.buyer.BuyerProfile;

import java.util.UUID;

public record HostedCheckoutCommand(
        // Payment
        UUID paymentId,
        String conversationId,
        long amountMinor,
        String currencyCode,

        // Checkout presentation
        CheckoutLocale locale,
        String itemName,

        // Buyer and provider customer
        BuyerProfile buyer,
        String providerCustomerKey
) {
}
