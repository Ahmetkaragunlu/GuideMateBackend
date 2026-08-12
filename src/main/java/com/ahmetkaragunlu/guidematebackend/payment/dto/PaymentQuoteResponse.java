package com.ahmetkaragunlu.guidematebackend.payment.dto;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record PaymentQuoteResponse(
        UUID quoteId,
        PaymentPurpose purpose,
        long baseAmountMinor,
        String baseCurrencyCode,
        long chargeAmountMinor,
        String chargeCurrencyCode,
        BigDecimal fxRate,
        String rateSource,
        LocalDate rateDate,
        Instant quotedAt,
        Instant expiresAt
) {
}
