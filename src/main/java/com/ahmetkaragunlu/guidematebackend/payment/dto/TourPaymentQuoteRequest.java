package com.ahmetkaragunlu.guidematebackend.payment.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record TourPaymentQuoteRequest(
        @NotNull UUID sessionId,
        @Min(value = 1, message = "{validation.participantCount.min}") int participantCount,
        @NotBlank @Size(min = 3, max = 3) String chargeCurrencyCode
) {
}
