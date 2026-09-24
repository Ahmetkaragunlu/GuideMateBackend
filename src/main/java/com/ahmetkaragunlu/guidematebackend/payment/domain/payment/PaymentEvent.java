package com.ahmetkaragunlu.guidematebackend.payment.domain.payment;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidCreatedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Getter
@Entity
@Table(
        name = "payment_events",
        indexes = @Index(
                name = "idx_payment_event_payment_occurred",
                columnList = "payment_id, occurred_at"
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PaymentEvent extends UuidCreatedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "payment_id", nullable = false, updatable = false)
    private Payment payment;

    @Column(name = "event_type", nullable = false, updatable = false, length = 64)
    private String eventType;

    @Column(name = "provider_event_id", unique = true, updatable = false, length = 128)
    private String providerEventId;

    @Column(name = "payload_hash", updatable = false, length = 64)
    private String payloadHash;

    @Column(name = "provider_status", updatable = false, length = 64)
    private String providerStatus;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    public PaymentEvent(
            Payment payment,
            String eventType,
            String providerEventId,
            String payloadHash,
            String providerStatus,
            Instant occurredAt
    ) {
        this.payment = Objects.requireNonNull(payment);
        this.eventType = Objects.requireNonNull(eventType);
        this.providerEventId = providerEventId;
        this.payloadHash = payloadHash;
        this.providerStatus = providerStatus;
        this.occurredAt = Objects.requireNonNull(occurredAt);
    }
}
