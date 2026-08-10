package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
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
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Getter
@Entity
@Table(
        name = "refunds",
        indexes = {
                @Index(name = "idx_refund_payment", columnList = "payment_id"),
                @Index(name = "idx_refund_status_updated", columnList = "status, updated_at")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_refund_idempotency",
                columnNames = {"payment_id", "idempotency_key"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Refund extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "payment_id", nullable = false, updatable = false)
    private Payment payment;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "requested_by", nullable = false, updatable = false)
    private User requestedBy;

    @Column(name = "amount_minor", nullable = false, updatable = false)
    private long amountMinor;

    @Column(name = "currency_code", nullable = false, updatable = false, length = 3)
    private String currencyCode;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private RefundStatus status;

    @Column(name = "provider_refund_id", unique = true)
    private String providerRefundId;

    @Column(name = "idempotency_key", nullable = false, updatable = false, length = 128)
    private String idempotencyKey;

    @Column(name = "failure_code", length = 64)
    private String failureCode;

    @Column(name = "requested_at", nullable = false, updatable = false)
    private Instant requestedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    private Refund(
            Payment payment,
            User requestedBy,
            long amountMinor,
            String currencyCode,
            String idempotencyKey,
            RefundStatus status,
            Instant requestedAt,
            Instant completedAt
    ) {
        this.payment = Objects.requireNonNull(payment);
        this.requestedBy = Objects.requireNonNull(requestedBy);
        this.amountMinor = amountMinor;
        this.currencyCode = Objects.requireNonNull(currencyCode);
        this.idempotencyKey = Objects.requireNonNull(idempotencyKey);
        this.status = Objects.requireNonNull(status);
        this.requestedAt = Objects.requireNonNull(requestedAt);
        this.completedAt = completedAt;
    }

    public static Refund requested(
            Payment payment,
            User requestedBy,
            long amountMinor,
            String idempotencyKey,
            Instant requestedAt
    ) {
        return new Refund(
                payment,
                requestedBy,
                amountMinor,
                payment.getCurrencyCode(),
                idempotencyKey,
                RefundStatus.REQUESTED,
                requestedAt,
                null
        );
    }

    public static Refund succeededWallet(
            Payment payment,
            User requestedBy,
            long amountMinor,
            String idempotencyKey,
            Instant completedAt
    ) {
        return new Refund(
                payment,
                requestedBy,
                amountMinor,
                payment.getCurrencyCode(),
                idempotencyKey,
                RefundStatus.SUCCEEDED,
                completedAt,
                completedAt
        );
    }

    public void markProcessing() {
        if (status == RefundStatus.PROCESSING || status == RefundStatus.SUCCEEDED) {
            return;
        }
        if (status != RefundStatus.REQUESTED && status != RefundStatus.FAILED) {
            throw new IllegalStateException("Refund cannot be processed from " + status);
        }
        this.status = RefundStatus.PROCESSING;
        this.failureCode = null;
    }

    public void succeed(String providerRefundId, Instant completedAt) {
        if (status == RefundStatus.SUCCEEDED) {
            return;
        }
        if (status != RefundStatus.PROCESSING && status != RefundStatus.REQUESTED) {
            throw new IllegalStateException("Refund cannot succeed from " + status);
        }
        this.providerRefundId = providerRefundId;
        this.completedAt = Objects.requireNonNull(completedAt);
        this.failureCode = null;
        this.status = RefundStatus.SUCCEEDED;
    }

    public void fail(String failureCode) {
        if (status == RefundStatus.SUCCEEDED) {
            throw new IllegalStateException("Succeeded refund cannot fail");
        }
        this.failureCode = failureCode;
        this.status = RefundStatus.FAILED;
    }

    public void requireManualReview(String failureCode) {
        if (status == RefundStatus.SUCCEEDED) {
            return;
        }
        this.failureCode = failureCode;
        this.status = RefundStatus.MANUAL_REVIEW;
    }
}
