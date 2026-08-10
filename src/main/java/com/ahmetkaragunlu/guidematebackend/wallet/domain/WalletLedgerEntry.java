package com.ahmetkaragunlu.guidematebackend.wallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "wallet_ledger_entries",
        indexes = {
                @Index(name = "idx_wallet_ledger_wallet_occurred", columnList = "wallet_id, occurred_at"),
                @Index(name = "idx_wallet_ledger_reference", columnList = "reference_type, reference_id")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_wallet_ledger_idempotency",
                columnNames = {"wallet_id", "idempotency_key"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WalletLedgerEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "wallet_id", nullable = false, updatable = false)
    private Wallet wallet;

    @Enumerated(EnumType.STRING)
    @Column(name = "direction", nullable = false, updatable = false, length = 16)
    private LedgerDirection direction;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, updatable = false, length = 32)
    private LedgerEntryType type;

    @Column(name = "amount_minor", nullable = false, updatable = false)
    private long amountMinor;

    @Column(name = "reference_type", nullable = false, updatable = false, length = 32)
    private String referenceType;

    @Column(name = "reference_id", nullable = false, updatable = false)
    private UUID referenceId;

    @Column(name = "idempotency_key", nullable = false, updatable = false, length = 128)
    private String idempotencyKey;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public WalletLedgerEntry(
            Wallet wallet,
            LedgerDirection direction,
            LedgerEntryType type,
            long amountMinor,
            String referenceType,
            UUID referenceId,
            String idempotencyKey,
            Instant occurredAt
    ) {
        this.wallet = Objects.requireNonNull(wallet);
        this.direction = Objects.requireNonNull(direction);
        this.type = Objects.requireNonNull(type);
        this.amountMinor = amountMinor;
        this.referenceType = Objects.requireNonNull(referenceType);
        this.referenceId = Objects.requireNonNull(referenceId);
        this.idempotencyKey = Objects.requireNonNull(idempotencyKey);
        this.occurredAt = Objects.requireNonNull(occurredAt);
    }
}
