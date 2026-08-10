package com.ahmetkaragunlu.guidematebackend.payment.dto;

import jakarta.validation.constraints.Positive;

public record WalletTopUpRequest(
        @Positive(message = "{validation.amount.positive}") long amountMinor
) {
}
