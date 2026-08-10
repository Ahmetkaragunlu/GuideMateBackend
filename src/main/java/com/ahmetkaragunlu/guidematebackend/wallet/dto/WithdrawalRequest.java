package com.ahmetkaragunlu.guidematebackend.wallet.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.util.UUID;

public record WithdrawalRequest(
        @NotNull UUID bankAccountId,
        @Positive(message = "{validation.amount.positive}") long amountMinor
) {
}
