package com.ahmetkaragunlu.guidematebackend.wallet.domain;

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

import java.util.Objects;

@Getter
@Entity
@Table(
        name = "bank_accounts",
        indexes = @Index(name = "idx_bank_account_guide_status", columnList = "guide_id, status"),
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_bank_account_iban", columnNames = {"guide_id", "iban_fingerprint"}),
                @UniqueConstraint(name = "uq_bank_account_default", columnNames = {"guide_id", "default_guard"})
        }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BankAccount extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "guide_id", nullable = false, updatable = false)
    private User guide;

    @Column(name = "iban_encrypted", nullable = false, updatable = false, columnDefinition = "text")
    private String ibanEncrypted;

    @Column(name = "iban_fingerprint", nullable = false, updatable = false, length = 64)
    private String ibanFingerprint;

    @Column(name = "masked_iban", nullable = false, updatable = false, length = 34)
    private String maskedIban;

    @Column(name = "bank_code", nullable = false, updatable = false, length = 8)
    private String bankCode;

    @Column(name = "bank_name", nullable = false, updatable = false, length = 128)
    private String bankName;

    @Column(name = "account_holder_name", nullable = false, updatable = false, length = 160)
    private String accountHolderName;

    @Column(name = "is_default", nullable = false)
    private boolean defaultAccount;

    @Column(name = "default_guard")
    private Boolean defaultGuard;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private BankAccountStatus status;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    public BankAccount(
            User guide,
            String ibanEncrypted,
            String ibanFingerprint,
            String maskedIban,
            String bankCode,
            String bankName,
            String accountHolderName,
            boolean defaultAccount
    ) {
        this.guide = Objects.requireNonNull(guide);
        this.ibanEncrypted = Objects.requireNonNull(ibanEncrypted);
        this.ibanFingerprint = Objects.requireNonNull(ibanFingerprint);
        this.maskedIban = Objects.requireNonNull(maskedIban);
        this.bankCode = Objects.requireNonNull(bankCode);
        this.bankName = Objects.requireNonNull(bankName);
        this.accountHolderName = Objects.requireNonNull(accountHolderName);
        this.status = BankAccountStatus.ACTIVE;
        setDefault(defaultAccount);
    }

    public void setDefault(boolean value) {
        if (status != BankAccountStatus.ACTIVE && value) {
            throw new IllegalStateException("Disabled bank account cannot be default");
        }
        this.defaultAccount = value;
        this.defaultGuard = value ? Boolean.TRUE : null;
    }

    public void disable() {
        this.status = BankAccountStatus.DISABLED;
        setDefault(false);
    }
}
