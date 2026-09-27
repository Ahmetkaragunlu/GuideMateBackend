package com.ahmetkaragunlu.guidematebackend.payment.dto.response;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record PaymentQuoteResponse(
        // Quote identity
        UUID quoteId,
        PaymentPurpose purpose,

        // Canonical amount
        long baseAmountMinor,
        String baseCurrencyCode,

        // Charge currency and exchange rate
        long chargeAmountMinor,
        String chargeCurrencyCode,
        BigDecimal fxRate,
        String rateSource,
        LocalDate rateDate,

        // Quote validity
        Instant quotedAt,
        Instant expiresAt
) {
}
