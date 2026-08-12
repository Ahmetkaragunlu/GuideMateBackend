package com.ahmetkaragunlu.guidematebackend.payment.dto;

import com.ahmetkaragunlu.guidematebackend.payment.domain.CheckoutLocale;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record WalletTopUpRequest(
        @NotNull UUID quoteId,
        @NotNull CheckoutLocale locale
) {
}
