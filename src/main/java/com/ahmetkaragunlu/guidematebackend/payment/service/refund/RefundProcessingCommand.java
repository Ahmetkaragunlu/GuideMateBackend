package com.ahmetkaragunlu.guidematebackend.payment.service.refund;

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
