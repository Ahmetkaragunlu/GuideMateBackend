package com.ahmetkaragunlu.guidematebackend.wallet.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Getter
@Entity
@Table(
        name = "guide_earnings",
        indexes = @Index(
                name = "idx_guide_earning_status_available",
                columnList = "status, available_at"
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class GuideEarning extends UuidAuditedEntity {

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "reservation_id", nullable = false, unique = true, updatable = false)
    private Reservation reservation;

    @Column(name = "gross_minor", nullable = false, updatable = false)
    private long grossMinor;

    @Column(name = "platform_fee_minor", nullable = false, updatable = false)
    private long platformFeeMinor;

    @Column(name = "net_minor", nullable = false, updatable = false)
    private long netMinor;

    @Column(name = "currency_code", nullable = false, updatable = false, length = 3)
    private String currencyCode;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private GuideEarningStatus status;

    @Column(name = "available_at", nullable = false, updatable = false)
    private Instant availableAt;

    @Column(name = "reversed_at")
    private Instant reversedAt;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    public GuideEarning(
            Reservation reservation,
            long grossMinor,
            long platformFeeMinor,
            long netMinor,
            String currencyCode,
            Instant availableAt
    ) {
        this.reservation = Objects.requireNonNull(reservation);
        this.grossMinor = grossMinor;
        this.platformFeeMinor = platformFeeMinor;
        this.netMinor = netMinor;
        this.currencyCode = Objects.requireNonNull(currencyCode);
        this.availableAt = Objects.requireNonNull(availableAt);
        this.status = GuideEarningStatus.PENDING;
    }

    public void makeAvailable() {
        if (status == GuideEarningStatus.AVAILABLE) {
            return;
        }
        if (status != GuideEarningStatus.PENDING) {
            throw new IllegalStateException("Earning cannot become available from " + status);
        }
        this.status = GuideEarningStatus.AVAILABLE;
    }

    public GuideEarningStatus reverse(Instant reversedAt) {
        GuideEarningStatus previous = status;
        if (status == GuideEarningStatus.REVERSED) {
            return previous;
        }
        this.status = GuideEarningStatus.REVERSED;
        this.reversedAt = Objects.requireNonNull(reversedAt);
        return previous;
    }
}
