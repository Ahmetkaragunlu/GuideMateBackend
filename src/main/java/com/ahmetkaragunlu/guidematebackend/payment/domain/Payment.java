package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
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
        name = "payments",
        indexes = {
                @Index(name = "idx_payment_user_created", columnList = "user_id, created_at"),
                @Index(name = "idx_payment_reservation", columnList = "reservation_id"),
                @Index(name = "idx_payment_status_updated", columnList = "status, updated_at")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_payment_idempotency",
                columnNames = {"user_id", "purpose", "idempotency_key"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Payment extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, updatable = false, length = 32)
    private PaymentPurpose purpose;

    @Enumerated(EnumType.STRING)
    @Column(name = "method", nullable = false, updatable = false, length = 32)
    private PaymentMethod method;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reservation_id", updatable = false)
    private Reservation reservation;

    @Column(name = "amount_minor", nullable = false, updatable = false)
    private long amountMinor;

    @Column(name = "currency_code", nullable = false, updatable = false, length = 3)
    private String currencyCode;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private PaymentStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", length = 32, updatable = false)
    private PaymentProvider provider;

    @Column(name = "provider_payment_id", unique = true)
    private String providerPaymentId;

    @Column(name = "provider_transaction_id", unique = true)
    private String providerTransactionId;

    @Column(name = "provider_token_encrypted", columnDefinition = "text")
    private String providerTokenEncrypted;

    @Column(name = "provider_token_fingerprint", length = 64, unique = true)
    private String providerTokenFingerprint;

    @Column(name = "provider_conversation_id")
    private String providerConversationId;

    @Column(name = "payment_page_url", columnDefinition = "text")
    private String paymentPageUrl;

    @Column(name = "idempotency_key", nullable = false, updatable = false, length = 128)
    private String idempotencyKey;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "failure_code", length = 64)
    private String failureCode;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    private Payment(
            User user,
            PaymentPurpose purpose,
            PaymentMethod method,
            Reservation reservation,
            long amountMinor,
            String currencyCode,
            PaymentProvider provider,
            String idempotencyKey,
            PaymentStatus status,
            Instant verifiedAt
    ) {
        this.user = Objects.requireNonNull(user);
        this.purpose = Objects.requireNonNull(purpose);
        this.method = Objects.requireNonNull(method);
        this.reservation = reservation;
        this.amountMinor = amountMinor;
        this.currencyCode = Objects.requireNonNull(currencyCode);
        this.provider = provider;
        this.idempotencyKey = Objects.requireNonNull(idempotencyKey);
        this.status = Objects.requireNonNull(status);
        this.verifiedAt = verifiedAt;
    }

    public static Payment hosted(
            User user,
            PaymentPurpose purpose,
            Reservation reservation,
            long amountMinor,
            String currencyCode,
            String idempotencyKey
    ) {
        return new Payment(
                user,
                purpose,
                PaymentMethod.HOSTED_CARD,
                reservation,
                amountMinor,
                currencyCode,
                PaymentProvider.IYZICO,
                idempotencyKey,
                PaymentStatus.PENDING,
                null
        );
    }

    public static Payment wallet(
            User user,
            Reservation reservation,
            long amountMinor,
            String currencyCode,
            String idempotencyKey,
            Instant verifiedAt
    ) {
        return new Payment(
                user,
                PaymentPurpose.TOUR_BOOKING,
                PaymentMethod.WALLET,
                Objects.requireNonNull(reservation),
                amountMinor,
                currencyCode,
                null,
                idempotencyKey,
                PaymentStatus.SUCCEEDED,
                Objects.requireNonNull(verifiedAt)
        );
    }

    public void markRequiresAction(
            String encryptedToken,
            String tokenFingerprint,
            String conversationId,
            String pageUrl,
            Instant expiresAt
    ) {
        requireStatus(PaymentStatus.PENDING);
        this.providerTokenEncrypted = Objects.requireNonNull(encryptedToken);
        this.providerTokenFingerprint = Objects.requireNonNull(tokenFingerprint);
        this.providerConversationId = Objects.requireNonNull(conversationId);
        this.paymentPageUrl = Objects.requireNonNull(pageUrl);
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.status = PaymentStatus.REQUIRES_ACTION;
    }

    public void markVerifying() {
        if (status == PaymentStatus.VERIFYING || status == PaymentStatus.SUCCEEDED) {
            return;
        }
        if (status != PaymentStatus.PENDING
                && status != PaymentStatus.REQUIRES_ACTION
                && status != PaymentStatus.CANCELLED
                && status != PaymentStatus.TIMEOUT) {
            throw new IllegalStateException("Payment cannot be verified from " + status);
        }
        this.status = PaymentStatus.VERIFYING;
    }

    public void succeed(
            String providerPaymentId,
            String providerTransactionId,
            Instant verifiedAt
    ) {
        if (status == PaymentStatus.SUCCEEDED) {
            return;
        }
        if (status != PaymentStatus.PENDING
                && status != PaymentStatus.REQUIRES_ACTION
                && status != PaymentStatus.VERIFYING
                && status != PaymentStatus.CANCELLED
                && status != PaymentStatus.TIMEOUT
                && status != PaymentStatus.FAILED) {
            throw new IllegalStateException("Payment cannot succeed from " + status);
        }
        this.providerPaymentId = Objects.requireNonNull(providerPaymentId);
        this.providerTransactionId = Objects.requireNonNull(providerTransactionId);
        this.verifiedAt = Objects.requireNonNull(verifiedAt);
        this.failureCode = null;
        this.status = PaymentStatus.SUCCEEDED;
    }

    public void fail(String failureCode) {
        if (status == PaymentStatus.SUCCEEDED || status == PaymentStatus.CANCELLED) {
            throw new IllegalStateException("Payment cannot fail from " + status);
        }
        this.failureCode = failureCode;
        this.status = PaymentStatus.FAILED;
    }

    public void cancel() {
        if (status == PaymentStatus.CANCELLED) {
            return;
        }
        if (status != PaymentStatus.PENDING && status != PaymentStatus.REQUIRES_ACTION) {
            throw new IllegalStateException("Payment cannot be cancelled from " + status);
        }
        this.status = PaymentStatus.CANCELLED;
    }

    public void timeout() {
        if (status.isTerminal()) {
            return;
        }
        this.status = PaymentStatus.TIMEOUT;
    }

    private void requireStatus(PaymentStatus expected) {
        if (status != expected) {
            throw new IllegalStateException("Expected payment status " + expected + " but was " + status);
        }
    }
}
