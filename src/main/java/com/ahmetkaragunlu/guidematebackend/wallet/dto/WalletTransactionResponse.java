package com.ahmetkaragunlu.guidematebackend.wallet.dto;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerDirection;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;

import java.time.Instant;
import java.util.UUID;

public record WalletTransactionResponse(
        UUID transactionId,
        LedgerDirection direction,
        LedgerEntryType type,
        long amountMinor,
        String currencyCode,
        String referenceType,
        UUID referenceId,
        Instant occurredAt
) {
}
