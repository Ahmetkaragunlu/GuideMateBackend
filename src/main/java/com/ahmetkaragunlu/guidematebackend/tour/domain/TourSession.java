package com.ahmetkaragunlu.guidematebackend.tour.domain;

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
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

@Getter
@Entity
@Table(name = "tour_sessions", indexes = {
        @Index(name = "idx_tour_session_tour", columnList = "tour_id"),
        @Index(name = "idx_tour_session_status_start", columnList = "status, starts_at")
})
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TourSession extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tour_id", nullable = false, updatable = false)
    private Tour tour;

    @Column(name = "meeting_point", nullable = false, length = 500)
    private String meetingPoint;

    @Column(name = "starts_at", nullable = false)
    private Instant startsAt;

    @Column(name = "duration_minutes", nullable = false)
    private int durationMinutes;

    @Column(name = "price_minor", nullable = false)
    private long priceMinor;

    @Column(name = "currency_code", nullable = false, length = 3)
    private String currencyCode;

    @Column(name = "capacity", nullable = false)
    private int capacity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private TourSessionStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "cancellation_actor", length = 16)
    private TourCancellationActor cancellationActor;

    @Column(name = "cancellation_reason", length = 1000)
    private String cancellationReason;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    private TourSession(
            Tour tour,
            String meetingPoint,
            Instant startsAt,
            int durationMinutes,
            long priceMinor,
            String currencyCode,
            int capacity,
            TourSessionStatus status
    ) {
        this.tour = Objects.requireNonNull(tour);
        updateSchedule(meetingPoint, startsAt, durationMinutes, priceMinor, capacity);
        this.currencyCode = Objects.requireNonNull(currencyCode);
        this.status = Objects.requireNonNull(status);
    }

    public static TourSession create(
            Tour tour,
            String meetingPoint,
            Instant startsAt,
            int durationMinutes,
            long priceMinor,
            String currencyCode,
            int capacity,
            TourSessionStatus status
    ) {
        return new TourSession(
                tour,
                meetingPoint,
                startsAt,
                durationMinutes,
                priceMinor,
                currencyCode,
                capacity,
                status
        );
    }

    public Instant endsAt() {
        return startsAt.plus(durationMinutes, ChronoUnit.MINUTES);
    }

    public void updateSchedule(
            String meetingPoint,
            Instant startsAt,
            int durationMinutes,
            long priceMinor,
            int capacity
    ) {
        this.meetingPoint = Objects.requireNonNull(meetingPoint);
        this.startsAt = Objects.requireNonNull(startsAt);
        this.durationMinutes = durationMinutes;
        this.priceMinor = priceMinor;
        this.capacity = capacity;
    }

    public void open() {
        this.status = TourSessionStatus.OPEN_FOR_BOOKING;
    }

    public void close() {
        this.status = TourSessionStatus.CLOSED;
    }

    public void cancel(TourCancellationActor actor, String reason, Instant cancelledAt) {
        this.status = TourSessionStatus.CANCELLED;
        this.cancellationActor = Objects.requireNonNull(actor);
        this.cancellationReason = Objects.requireNonNull(reason);
        this.cancelledAt = Objects.requireNonNull(cancelledAt);
    }

    public void complete() {
        this.status = TourSessionStatus.COMPLETED;
    }
}
