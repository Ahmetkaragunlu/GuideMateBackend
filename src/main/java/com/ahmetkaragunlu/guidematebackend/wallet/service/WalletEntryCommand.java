package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;

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
