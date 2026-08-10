package com.ahmetkaragunlu.guidematebackend.wallet.dto;

import java.time.Instant;
import java.util.UUID;

public record BankAccountResponse(
        UUID bankAccountId,
        String maskedIban,
        String bankCode,
        String bankName,
        String accountHolderName,
        boolean defaultAccount,
        Instant createdAt
) {
}
