package com.ahmetkaragunlu.guidematebackend.payment.dto.request;

import com.ahmetkaragunlu.guidematebackend.payment.domain.checkout.CheckoutLocale;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record WalletTopUpRequest(
        @NotNull UUID quoteId,
        @NotNull CheckoutLocale locale
) {
}
