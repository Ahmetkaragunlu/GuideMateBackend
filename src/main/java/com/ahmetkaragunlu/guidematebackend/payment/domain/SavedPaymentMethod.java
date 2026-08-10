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

import java.util.Objects;

@Getter
@Entity
@Table(
        name = "saved_payment_methods",
        indexes = @Index(
                name = "idx_saved_payment_method_user_status",
                columnList = "user_id, status"
        ),
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uq_saved_payment_method_token",
                        columnNames = {"provider", "provider_card_token_fingerprint"}
                ),
                @UniqueConstraint(
                        name = "uq_saved_payment_method_default",
                        columnNames = {"user_id", "default_guard"}
                )
        }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SavedPaymentMethod extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, updatable = false, length = 32)
    private PaymentProvider provider;

    @Column(name = "provider_card_token_encrypted", nullable = false, updatable = false, columnDefinition = "text")
    private String providerCardTokenEncrypted;

    @Column(name = "provider_card_token_fingerprint", nullable = false, updatable = false, length = 64)
    private String providerCardTokenFingerprint;

    @Column(name = "alias", length = 100)
    private String alias;

    @Column(name = "bank_name", length = 128)
    private String bankName;

    @Column(name = "bank_code", length = 16)
    private String bankCode;

    @Column(name = "card_family", length = 64)
    private String cardFamily;

    @Column(name = "card_association", length = 32)
    private String cardAssociation;

    @Column(name = "card_type", length = 32)
    private String cardType;

    @Column(name = "last_four_digits", nullable = false, length = 4)
    private String lastFourDigits;

    @Column(name = "card_holder_name", length = 160)
    private String cardHolderName;

    @Column(name = "expiry_month")
    private Short expiryMonth;

    @Column(name = "expiry_year")
    private Short expiryYear;

    @Column(name = "is_default", nullable = false)
    private boolean defaultMethod;

    @Column(name = "default_guard")
    private Boolean defaultGuard;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private SavedPaymentMethodStatus status;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    public SavedPaymentMethod(
            User user,
            String providerCardTokenEncrypted,
            String providerCardTokenFingerprint,
            SavedCardMetadata metadata,
            boolean defaultMethod
    ) {
        this.user = Objects.requireNonNull(user);
        this.provider = PaymentProvider.IYZICO;
        this.providerCardTokenEncrypted = Objects.requireNonNull(providerCardTokenEncrypted);
        this.providerCardTokenFingerprint = Objects.requireNonNull(providerCardTokenFingerprint);
        this.status = SavedPaymentMethodStatus.ACTIVE;
        refreshMetadata(metadata);
        setDefault(defaultMethod);
    }

    public void refreshMetadata(SavedCardMetadata metadata) {
        Objects.requireNonNull(metadata);
        this.alias = preferNewValue(metadata.alias(), alias);
        this.bankName = preferNewValue(metadata.bankName(), bankName);
        this.bankCode = preferNewValue(metadata.bankCode(), bankCode);
        this.cardFamily = preferNewValue(metadata.cardFamily(), cardFamily);
        this.cardAssociation = preferNewValue(metadata.cardAssociation(), cardAssociation);
        this.cardType = preferNewValue(metadata.cardType(), cardType);
        this.lastFourDigits = requireLastFourDigits(metadata.lastFourDigits());
        this.cardHolderName = preferNewValue(metadata.cardHolderName(), cardHolderName);
        this.expiryMonth = metadata.expiryMonth() == null ? expiryMonth : metadata.expiryMonth();
        this.expiryYear = metadata.expiryYear() == null ? expiryYear : metadata.expiryYear();
        this.status = SavedPaymentMethodStatus.ACTIVE;
    }

    public void setDefault(boolean value) {
        if (status != SavedPaymentMethodStatus.ACTIVE && value) {
            throw new IllegalStateException("Inactive saved payment method cannot be default");
        }
        this.defaultMethod = value;
        this.defaultGuard = value ? Boolean.TRUE : null;
    }

    public void markDeleted() {
        this.status = SavedPaymentMethodStatus.DELETED;
        setDefault(false);
    }

    private String requireLastFourDigits(String value) {
        if (value == null || value.length() != 4 || !value.chars().allMatch(Character::isDigit)) {
            throw new IllegalArgumentException("Saved card last four digits are invalid");
        }
        return value;
    }

    private <T> T preferNewValue(T newValue, T currentValue) {
        return newValue == null ? currentValue : newValue;
    }
}
