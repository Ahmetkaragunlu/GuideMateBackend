package com.ahmetkaragunlu.guidematebackend.tour.domain;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "tour_change_requests",
        indexes = {
                @Index(name = "idx_tour_change_tour_status", columnList = "tour_id, status"),
                @Index(name = "idx_tour_change_submitted", columnList = "status, submitted_at"),
                @Index(name = "idx_tour_change_cover", columnList = "proposed_cover_media_id")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_tour_change_pending",
                columnNames = {"tour_id", "pending_guard"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TourChangeRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tour_id", nullable = false, updatable = false)
    private Tour tour;

    @Column(name = "base_version", nullable = false, updatable = false)
    private long baseVersion;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "proposed_snapshot", nullable = false, columnDefinition = "jsonb")
    private String proposedSnapshot;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "proposed_cover_media_id", nullable = false)
    private MediaAsset proposedCoverMedia;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private TourChangeRequestStatus status;

    @Column(name = "pending_guard")
    private Boolean pendingGuard;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "submitted_by", nullable = false, updatable = false)
    private User submittedBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by")
    private User reviewedBy;

    @Column(name = "submitted_at", nullable = false, updatable = false)
    private Instant submittedAt;

    @Column(name = "reviewed_at")
    private Instant reviewedAt;

    @Column(name = "rejection_reason", length = 1000)
    private String rejectionReason;

    private TourChangeRequest(
            Tour tour,
            long baseVersion,
            String proposedSnapshot,
            MediaAsset proposedCoverMedia,
            User submittedBy,
            Instant submittedAt
    ) {
        this.tour = Objects.requireNonNull(tour);
        this.baseVersion = baseVersion;
        this.proposedSnapshot = Objects.requireNonNull(proposedSnapshot);
        this.proposedCoverMedia = Objects.requireNonNull(proposedCoverMedia);
        this.status = TourChangeRequestStatus.PENDING;
        this.pendingGuard = true;
        this.submittedBy = Objects.requireNonNull(submittedBy);
        this.submittedAt = Objects.requireNonNull(submittedAt);
    }

    public static TourChangeRequest submit(
            Tour tour,
            long baseVersion,
            String proposedSnapshot,
            MediaAsset proposedCoverMedia,
            User submittedBy,
            Instant submittedAt
    ) {
        return new TourChangeRequest(
                tour,
                baseVersion,
                proposedSnapshot,
                proposedCoverMedia,
                submittedBy,
                submittedAt
        );
    }

    public void approve(User reviewer, Instant reviewedAt) {
        this.status = TourChangeRequestStatus.APPROVED;
        finishReview(reviewer, reviewedAt);
    }

    public void reject(User reviewer, String reason, Instant reviewedAt) {
        this.status = TourChangeRequestStatus.REJECTED;
        this.rejectionReason = Objects.requireNonNull(reason);
        finishReview(reviewer, reviewedAt);
    }

    private void finishReview(User reviewer, Instant reviewedAt) {
        this.reviewedBy = Objects.requireNonNull(reviewer);
        this.reviewedAt = Objects.requireNonNull(reviewedAt);
        this.pendingGuard = null;
    }
}
