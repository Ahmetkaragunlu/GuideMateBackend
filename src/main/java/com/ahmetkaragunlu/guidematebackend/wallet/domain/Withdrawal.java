package com.ahmetkaragunlu.guidematebackend.wallet.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
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
        name = "withdrawals",
        indexes = {
                @Index(name = "idx_withdrawal_wallet_requested", columnList = "wallet_id, requested_at"),
                @Index(name = "idx_withdrawal_status_updated", columnList = "status, updated_at")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_withdrawal_idempotency",
                columnNames = {"wallet_id", "idempotency_key"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Withdrawal extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "wallet_id", nullable = false, updatable = false)
    private Wallet wallet;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "bank_account_id", nullable = false, updatable = false)
    private BankAccount bankAccount;

    @Column(name = "amount_minor", nullable = false, updatable = false)
    private long amountMinor;

    @Column(name = "currency_code", nullable = false, updatable = false, length = 3)
    private String currencyCode;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private WithdrawalStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "payout_mode", nullable = false, updatable = false, length = 16)
    private PayoutMode payoutMode;

    @Column(name = "idempotency_key", nullable = false, updatable = false, length = 128)
    private String idempotencyKey;

    @Column(name = "provider_reference")
    private String providerReference;

    @Column(name = "failure_code", length = 64)
    private String failureCode;

    @Column(name = "requested_at", nullable = false, updatable = false)
    private Instant requestedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    public Withdrawal(
            Wallet wallet,
            BankAccount bankAccount,
            long amountMinor,
            PayoutMode payoutMode,
            String idempotencyKey,
            Instant requestedAt
    ) {
        this.wallet = Objects.requireNonNull(wallet);
        this.bankAccount = Objects.requireNonNull(bankAccount);
        this.amountMinor = amountMinor;
        this.currencyCode = wallet.getCurrencyCode();
        this.payoutMode = Objects.requireNonNull(payoutMode);
        this.idempotencyKey = Objects.requireNonNull(idempotencyKey);
        this.requestedAt = Objects.requireNonNull(requestedAt);
        this.status = WithdrawalStatus.PENDING;
    }

    public void markProcessing() {
        if (status != WithdrawalStatus.PENDING) {
            throw new IllegalStateException("Withdrawal cannot be processed from " + status);
        }
        this.status = WithdrawalStatus.PROCESSING;
    }

    public void complete(String reference, Instant completedAt) {
        if (status == WithdrawalStatus.COMPLETED) {
            return;
        }
        if (status != WithdrawalStatus.PENDING && status != WithdrawalStatus.PROCESSING) {
            throw new IllegalStateException("Withdrawal cannot complete from " + status);
        }
        this.providerReference = reference;
        this.completedAt = Objects.requireNonNull(completedAt);
        this.status = WithdrawalStatus.COMPLETED;
    }

    public void fail(String failureCode) {
        if (status == WithdrawalStatus.COMPLETED) {
            throw new IllegalStateException("Completed withdrawal cannot fail");
        }
        this.failureCode = failureCode;
        this.status = WithdrawalStatus.FAILED;
    }
}
