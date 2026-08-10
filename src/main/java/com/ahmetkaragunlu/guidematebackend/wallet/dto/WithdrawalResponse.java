package com.ahmetkaragunlu.guidematebackend.wallet.dto;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WithdrawalStatus;

import java.time.Instant;
import java.util.UUID;

public record WithdrawalResponse(
        UUID withdrawalId,
        UUID bankAccountId,
        String maskedIban,
        long amountMinor,
        String currencyCode,
        WithdrawalStatus status,
        PayoutMode payoutMode,
        Instant requestedAt,
        Instant completedAt,
        String failureCode
) {
}
