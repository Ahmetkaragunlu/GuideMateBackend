package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Objects;

@Getter
@Entity
@Table(
        name = "payment_provider_customers",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_payment_provider_customer_key",
                columnNames = {"provider", "provider_customer_key_fingerprint"}
        )
)
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PaymentProviderCustomer {

    @Id
    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, updatable = false, length = 32)
    private PaymentProvider provider;

    @Column(name = "provider_customer_key_encrypted", nullable = false, updatable = false, columnDefinition = "text")
    private String providerCustomerKeyEncrypted;

    @Column(name = "provider_customer_key_fingerprint", nullable = false, updatable = false, length = 64)
    private String providerCustomerKeyFingerprint;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public PaymentProviderCustomer(
            User user,
            String providerCustomerKeyEncrypted,
            String providerCustomerKeyFingerprint
    ) {
        this.user = Objects.requireNonNull(user);
        this.provider = PaymentProvider.IYZICO;
        this.providerCustomerKeyEncrypted = Objects.requireNonNull(providerCustomerKeyEncrypted);
        this.providerCustomerKeyFingerprint = Objects.requireNonNull(providerCustomerKeyFingerprint);
    }
}
