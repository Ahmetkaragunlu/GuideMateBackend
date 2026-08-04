package com.ahmetkaragunlu.guidematebackend.reservation.domain;

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
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Objects;

@Getter
@Entity
@Table(
        name = "reservations",
        indexes = {
                @Index(name = "idx_reservation_session_status", columnList = "session_id, status"),
                @Index(name = "idx_reservation_tourist_created", columnList = "tourist_id, created_at"),
                @Index(name = "idx_reservation_hold_expiry", columnList = "status, hold_expires_at")
        },
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uq_reservation_active",
                        columnNames = {"session_id", "tourist_id", "active_guard"}
                ),
                @UniqueConstraint(
                        name = "uq_reservation_booking_idempotency",
                        columnNames = {"tourist_id", "idempotency_key"}
                ),
                @UniqueConstraint(
                        name = "uq_reservation_cancel_idempotency",
                        columnNames = {"tourist_id", "cancellation_idempotency_key"}
                )
        }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Reservation extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false, updatable = false)
    private TourSession session;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tourist_id", nullable = false, updatable = false)
    private User tourist;

    @Column(name = "participant_count", nullable = false, updatable = false)
    private int participantCount;

    @Column(name = "unit_price_minor", nullable = false, updatable = false)
    private long unitPriceMinor;

    @Column(name = "total_price_minor", nullable = false, updatable = false)
    private long totalPriceMinor;

    @Column(name = "currency_code", nullable = false, updatable = false, length = 3)
    private String currencyCode;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private ReservationStatus status;

    @Column(name = "hold_expires_at")
    private Instant holdExpiresAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "cancellation_actor", length = 16)
    private ReservationCancellationActor cancellationActor;

    @Column(name = "cancellation_reason", length = 1000)
    private String cancellationReason;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "cancellation_refund_eligibility", length = 16)
    private RefundEligibility cancellationRefundEligibility;

    @Column(name = "cancellation_policy_code", nullable = false, updatable = false, length = 64)
    private String cancellationPolicyCode;

    @Column(name = "cancellation_policy_version", nullable = false, updatable = false)
    private int cancellationPolicyVersion;

    @Column(name = "snapshot_version", nullable = false, updatable = false)
    private int snapshotVersion;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "purchase_snapshot", nullable = false, updatable = false, columnDefinition = "jsonb")
    private String purchaseSnapshot;

    @Column(name = "idempotency_key", nullable = false, updatable = false, length = 128)
    private String idempotencyKey;

    @Column(name = "cancellation_idempotency_key", length = 128)
    private String cancellationIdempotencyKey;

    @Column(name = "active_guard")
    private Boolean activeGuard;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    private Reservation(
            TourSession session,
            User tourist,
            int participantCount,
            long unitPriceMinor,
            long totalPriceMinor,
            String currencyCode,
            Instant holdExpiresAt,
            String cancellationPolicyCode,
            int cancellationPolicyVersion,
            int snapshotVersion,
            String purchaseSnapshot,
            String idempotencyKey
    ) {
        this.session = Objects.requireNonNull(session);
        this.tourist = Objects.requireNonNull(tourist);
        this.participantCount = participantCount;
        this.unitPriceMinor = unitPriceMinor;
        this.totalPriceMinor = totalPriceMinor;
        this.currencyCode = Objects.requireNonNull(currencyCode);
        this.status = ReservationStatus.PENDING_PAYMENT;
        this.holdExpiresAt = Objects.requireNonNull(holdExpiresAt);
        this.cancellationPolicyCode = Objects.requireNonNull(cancellationPolicyCode);
        this.cancellationPolicyVersion = cancellationPolicyVersion;
        this.snapshotVersion = snapshotVersion;
        this.purchaseSnapshot = Objects.requireNonNull(purchaseSnapshot);
        this.idempotencyKey = Objects.requireNonNull(idempotencyKey);
        this.activeGuard = true;
    }

    public static Reservation hold(
            TourSession session,
            User tourist,
            int participantCount,
            long unitPriceMinor,
            long totalPriceMinor,
            String currencyCode,
            Instant holdExpiresAt,
            String cancellationPolicyCode,
            int cancellationPolicyVersion,
            int snapshotVersion,
            String purchaseSnapshot,
            String idempotencyKey
    ) {
        return new Reservation(
                session,
                tourist,
                participantCount,
                unitPriceMinor,
                totalPriceMinor,
                currencyCode,
                holdExpiresAt,
                cancellationPolicyCode,
                cancellationPolicyVersion,
                snapshotVersion,
                purchaseSnapshot,
                idempotencyKey
        );
    }

    public boolean isHoldExpired(Instant now) {
        return status == ReservationStatus.PENDING_PAYMENT
                && !holdExpiresAt.isAfter(now);
    }

    public void confirm() {
        requireStatus(ReservationStatus.PENDING_PAYMENT);
        this.status = ReservationStatus.CONFIRMED;
        this.holdExpiresAt = null;
    }

    public void expire() {
        requireStatus(ReservationStatus.PENDING_PAYMENT);
        this.status = ReservationStatus.EXPIRED;
        this.activeGuard = null;
    }

    public void cancel(
            ReservationCancellationActor actor,
            String reason,
            Instant cancelledAt,
            String cancellationIdempotencyKey,
            RefundEligibility refundEligibility
    ) {
        if (status != ReservationStatus.PENDING_PAYMENT && status != ReservationStatus.CONFIRMED) {
            throw new IllegalStateException("Reservation cannot be cancelled from " + status);
        }
        this.status = ReservationStatus.CANCELLED;
        this.cancellationActor = Objects.requireNonNull(actor);
        this.cancellationReason = reason;
        this.cancelledAt = Objects.requireNonNull(cancelledAt);
        this.cancellationIdempotencyKey = cancellationIdempotencyKey;
        this.cancellationRefundEligibility = Objects.requireNonNull(refundEligibility);
        this.holdExpiresAt = null;
        this.activeGuard = null;
    }

    public void complete() {
        requireStatus(ReservationStatus.CONFIRMED);
        this.status = ReservationStatus.COMPLETED;
        this.activeGuard = null;
    }

    private void requireStatus(ReservationStatus expected) {
        if (status != expected) {
            throw new IllegalStateException("Expected reservation status " + expected + " but was " + status);
        }
    }
}
