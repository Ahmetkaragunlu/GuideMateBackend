package com.ahmetkaragunlu.guidematebackend.payment.dto.response;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;

import java.time.Instant;
import java.math.BigDecimal;
import java.util.UUID;

public record PaymentResponse(
        // Payment identity and state
        UUID paymentId,
        PaymentPurpose purpose,
        PaymentMethod method,
        PaymentStatus paymentStatus,

        // Canonical amount
        long amountMinor,
        String currencyCode,

        // Charge currency and exchange rate
        UUID quoteId,
        Long chargeAmountMinor,
        String chargeCurrencyCode,
        BigDecimal fxRate,
        String fxRateSource,
        Instant fxQuotedAt,

        // Hosted checkout
        String paymentPageUrl,
        Instant expiresAt,

        // Reservation outcome
        UUID reservationId,
        ReservationStatus reservationStatus,

        // Refund outcome
        UUID refundId,
        RefundStatus refundStatus,
        Long refundAmountMinor,
        Long refundChargeAmountMinor,
        String refundChargeCurrencyCode,

        // Result metadata
        String failureCode,
        Instant createdAt,
        Instant updatedAt
) {
}
