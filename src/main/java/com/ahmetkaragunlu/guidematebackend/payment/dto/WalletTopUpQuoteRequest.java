package com.ahmetkaragunlu.guidematebackend.payment.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record WalletTopUpQuoteRequest(
        @Positive(message = "{validation.amount.positive}") long amountMinor,
        @NotBlank @Size(min = 3, max = 3) String chargeCurrencyCode
) {
}
