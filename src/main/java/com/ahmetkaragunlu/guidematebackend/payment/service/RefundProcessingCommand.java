package com.ahmetkaragunlu.guidematebackend.payment.service;

import java.util.UUID;

public record RefundProcessingCommand(
        UUID refundId,
        String conversationId,
        String providerTransactionId,
        long chargeAmountMinor,
        String chargeCurrencyCode,
        String ipAddress
) {
}
