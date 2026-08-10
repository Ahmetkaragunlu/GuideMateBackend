package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import java.util.UUID;

public record HostedCheckoutCommand(
        UUID paymentId,
        String conversationId,
        long amountMinor,
        String currencyCode,
        String itemName,
        BuyerProfile buyer,
        String providerCustomerKey
) {
}
