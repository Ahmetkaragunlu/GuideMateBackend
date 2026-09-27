package com.ahmetkaragunlu.guidematebackend.wallet.service.account;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;

import java.time.Instant;
import java.util.UUID;

public record WalletEntryCommand(
        long amountMinor,
        LedgerEntryType type,
        String referenceType,
        UUID referenceId,
        String idempotencyKey,
        Instant occurredAt
) {
}
