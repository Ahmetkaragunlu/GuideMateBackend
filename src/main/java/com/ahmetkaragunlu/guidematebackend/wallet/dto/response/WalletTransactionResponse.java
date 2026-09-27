package com.ahmetkaragunlu.guidematebackend.wallet.dto.response;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerDirection;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;

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
        String referenceTitle,
        Instant occurredAt
) {
}
