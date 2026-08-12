package com.ahmetkaragunlu.guidematebackend.payment.dto;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.CheckoutLocale;
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
