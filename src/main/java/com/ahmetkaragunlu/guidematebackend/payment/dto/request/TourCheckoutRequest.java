package com.ahmetkaragunlu.guidematebackend.payment.dto.request;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.checkout.CheckoutLocale;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record TourCheckoutRequest(
        @NotNull UUID sessionId,
        @Min(value = 1, message = "{validation.participantCount.min}") int participantCount,
        @NotNull PaymentMethod method,
        UUID quoteId,
        CheckoutLocale locale
) {
}
