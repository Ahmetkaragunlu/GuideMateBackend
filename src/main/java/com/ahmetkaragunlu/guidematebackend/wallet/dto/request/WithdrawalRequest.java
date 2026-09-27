package com.ahmetkaragunlu.guidematebackend.wallet.dto.request;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.util.UUID;

public record WithdrawalRequest(
        @NotNull(message = "{validation.bankAccountId.notNull}") UUID bankAccountId,
        @Positive(message = "{validation.amount.positive}") long amountMinor
) {
}
