package com.ahmetkaragunlu.guidematebackend.review.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Getter
@Entity
@Table(name = "reviews", indexes = @Index(name = "idx_review_created", columnList = "created_at"))
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Review extends UuidAuditedEntity {

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "reservation_id", nullable = false, updatable = false, unique = true)
    private Reservation reservation;

    @Column(name = "rating", nullable = false, updatable = false)
    private short rating;

    @Column(name = "comment", updatable = false, length = 2000)
    private String comment;

    private Review(Reservation reservation, int rating, String comment) {
        this.reservation = Objects.requireNonNull(reservation);
        if (rating < 1 || rating > 5) {
            throw new IllegalArgumentException("Review rating must be between 1 and 5");
        }
        this.rating = (short) rating;
        this.comment = comment;
    }

    public static Review submit(Reservation reservation, int rating, String comment) {
        return new Review(reservation, rating, comment);
    }
}
