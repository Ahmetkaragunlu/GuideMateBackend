package com.ahmetkaragunlu.guidematebackend.payment.dto;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;

import java.time.Instant;
import java.math.BigDecimal;
import java.util.UUID;

public record PaymentResponse(
        UUID paymentId,
        PaymentPurpose purpose,
        PaymentMethod method,
        PaymentStatus paymentStatus,
        long amountMinor,
        String currencyCode,
        UUID quoteId,
        Long chargeAmountMinor,
        String chargeCurrencyCode,
        BigDecimal fxRate,
        String fxRateSource,
        Instant fxQuotedAt,
        String paymentPageUrl,
        Instant expiresAt,
        UUID reservationId,
        ReservationStatus reservationStatus,
        UUID refundId,
        RefundStatus refundStatus,
        Long refundAmountMinor,
        Long refundChargeAmountMinor,
        String refundChargeCurrencyCode,
        String failureCode,
        Instant createdAt,
        Instant updatedAt
) {
}
