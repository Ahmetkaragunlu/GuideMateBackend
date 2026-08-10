package com.ahmetkaragunlu.guidematebackend.payment.service;

import java.util.UUID;

public record RefundProcessingCommand(
        UUID refundId,
        String conversationId,
        String providerTransactionId,
        long amountMinor,
        String currencyCode,
        String ipAddress
) {
}
