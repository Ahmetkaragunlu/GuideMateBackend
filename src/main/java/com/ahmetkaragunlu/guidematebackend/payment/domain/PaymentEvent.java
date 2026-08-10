package com.ahmetkaragunlu.guidematebackend.payment.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
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
        name = "payment_events",
        indexes = @Index(
                name = "idx_payment_event_payment_occurred",
                columnList = "payment_id, occurred_at"
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PaymentEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

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

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

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
