package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Objects;

@Getter
@Entity
@Table(
        name = "payment_fx_quotes",
        indexes = @Index(name = "idx_payment_fx_quote_user_expiry", columnList = "user_id, expires_at")
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PaymentFxQuote extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, updatable = false, length = 32)
    private PaymentPurpose purpose;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", updatable = false)
    private TourSession session;

    @Column(name = "participant_count", updatable = false)
    private Integer participantCount;

    @Column(name = "base_amount_minor", nullable = false, updatable = false)
    private long baseAmountMinor;

    @Column(name = "base_currency_code", nullable = false, updatable = false, length = 3)
    private String baseCurrencyCode;

    @Column(name = "charge_amount_minor", nullable = false, updatable = false)
    private long chargeAmountMinor;

    @Column(name = "charge_currency_code", nullable = false, updatable = false, length = 3)
    private String chargeCurrencyCode;

    @Column(name = "fx_rate", nullable = false, updatable = false, precision = 24, scale = 12)
    private BigDecimal fxRate;

    @Column(name = "rate_source", nullable = false, updatable = false, length = 64)
    private String rateSource;

    @Column(name = "rate_date", nullable = false, updatable = false)
    private LocalDate rateDate;

    @Column(name = "quoted_at", nullable = false, updatable = false)
    private Instant quotedAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    private PaymentFxQuote(
            User user,
            PaymentPurpose purpose,
            TourSession session,
            Integer participantCount,
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
        this.user = Objects.requireNonNull(user);
        this.purpose = Objects.requireNonNull(purpose);
        this.session = session;
        this.participantCount = participantCount;
        this.baseAmountMinor = baseAmountMinor;
        this.baseCurrencyCode = Objects.requireNonNull(baseCurrencyCode);
        this.chargeAmountMinor = chargeAmountMinor;
        this.chargeCurrencyCode = Objects.requireNonNull(chargeCurrencyCode);
        this.fxRate = Objects.requireNonNull(fxRate);
        this.rateSource = Objects.requireNonNull(rateSource);
        this.rateDate = Objects.requireNonNull(rateDate);
        this.quotedAt = Objects.requireNonNull(quotedAt);
        this.expiresAt = Objects.requireNonNull(expiresAt);
    }

    public static PaymentFxQuote tour(
            User user,
            TourSession session,
            int participantCount,
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
        return new PaymentFxQuote(
                user,
                PaymentPurpose.TOUR_BOOKING,
                Objects.requireNonNull(session),
                participantCount,
                baseAmountMinor,
                baseCurrencyCode,
                chargeAmountMinor,
                chargeCurrencyCode,
                fxRate,
                rateSource,
                rateDate,
                quotedAt,
                expiresAt
        );
    }

    public static PaymentFxQuote walletTopUp(
            User user,
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
        return new PaymentFxQuote(
                user,
                PaymentPurpose.WALLET_TOP_UP,
                null,
                null,
                baseAmountMinor,
                baseCurrencyCode,
                chargeAmountMinor,
                chargeCurrencyCode,
                fxRate,
                rateSource,
                rateDate,
                quotedAt,
                expiresAt
        );
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }
}
