package com.ahmetkaragunlu.guidematebackend.wallet.dto.response;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.payout.PayoutMode;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.payout.WithdrawalStatus;

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
