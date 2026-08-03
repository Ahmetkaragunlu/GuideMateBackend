package com.ahmetkaragunlu.guidematebackend.tour.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
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
import org.hibernate.annotations.BatchSize;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

@Getter
@Entity
@Table(name = "tours", indexes = {
        @Index(name = "idx_tour_guide_status", columnList = "guide_id, approval_status"),
        @Index(name = "idx_tour_cover", columnList = "cover_media_id"),
        @Index(name = "idx_tour_public_location", columnList = "approval_status, country_code, city_place_id, category_code")
})
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Tour extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "guide_id", nullable = false, updatable = false)
    private User guide;

    @Column(name = "title", nullable = false, length = 120)
    private String title;

    @Column(name = "description", nullable = false, length = 3000)
    private String description;

    @Column(name = "country_code", nullable = false, length = 2)
    private String countryCode;

    @Column(name = "city_place_id", nullable = false, length = 255)
    private String cityPlaceId;

    @Column(name = "city_name", nullable = false, length = 120)
    private String cityName;

    @Column(name = "time_zone_id", nullable = false, length = 64)
    private String timeZoneId;

    @Column(name = "category_code", nullable = false, length = 32)
    private String categoryCode;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "cover_media_id", nullable = false)
    private MediaAsset coverMedia;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "tour_languages", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "language_code", nullable = false, length = 3)
    @BatchSize(size = 50)
    private Set<String> languageCodes = new LinkedHashSet<>();

    @Enumerated(EnumType.STRING)
    @Column(name = "approval_status", nullable = false, length = 32)
    private TourApprovalStatus approvalStatus;

    @Column(name = "submitted_at", nullable = false)
    private Instant submittedAt;

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "reviewed_at")
    private Instant reviewedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by")
    private User reviewedBy;

    @Column(name = "rejection_reason", length = 1000)
    private String rejectionReason;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    private Tour(
            User guide,
            TourChangeSnapshot details,
            MediaAsset coverMedia,
            Instant submittedAt
    ) {
        this.guide = Objects.requireNonNull(guide);
        applyDetails(details, coverMedia);
        this.approvalStatus = TourApprovalStatus.PENDING_REVIEW;
        this.submittedAt = Objects.requireNonNull(submittedAt);
    }

    public static Tour submit(
            User guide,
            TourChangeSnapshot details,
            MediaAsset coverMedia,
            Instant submittedAt
    ) {
        return new Tour(guide, details, coverMedia, submittedAt);
    }

    public boolean isOwnedBy(Long userId) {
        return userId != null && guide.getId().equals(userId);
    }

    public boolean isPublic() {
        return approvalStatus == TourApprovalStatus.APPROVED;
    }

    public void approve(User reviewer, Instant reviewedAt) {
        this.approvalStatus = TourApprovalStatus.APPROVED;
        this.reviewedBy = Objects.requireNonNull(reviewer);
        this.reviewedAt = Objects.requireNonNull(reviewedAt);
        this.publishedAt = this.publishedAt == null ? reviewedAt : this.publishedAt;
        this.rejectionReason = null;
    }

    public void reject(User reviewer, String reason, Instant reviewedAt) {
        this.approvalStatus = TourApprovalStatus.REJECTED;
        this.reviewedBy = Objects.requireNonNull(reviewer);
        this.reviewedAt = Objects.requireNonNull(reviewedAt);
        this.rejectionReason = Objects.requireNonNull(reason);
    }

    public void resubmit(TourChangeSnapshot details, MediaAsset coverMedia, Instant submittedAt) {
        applyDetails(details, coverMedia);
        this.approvalStatus = TourApprovalStatus.PENDING_REVIEW;
        this.submittedAt = Objects.requireNonNull(submittedAt);
        this.reviewedAt = null;
        this.reviewedBy = null;
        this.rejectionReason = null;
    }

    public void applyApprovedChange(TourChangeSnapshot details, MediaAsset coverMedia) {
        applyDetails(details, coverMedia);
    }

    public void archive() {
        this.approvalStatus = TourApprovalStatus.ARCHIVED;
    }

    private void applyDetails(TourChangeSnapshot details, MediaAsset coverMedia) {
        this.title = details.title();
        this.description = details.description();
        this.countryCode = details.countryCode();
        this.cityPlaceId = details.cityPlaceId();
        this.cityName = details.cityName();
        this.timeZoneId = details.timeZoneId();
        this.categoryCode = details.categoryCode();
        this.coverMedia = Objects.requireNonNull(coverMedia);
        this.languageCodes.clear();
        this.languageCodes.addAll(details.languageCodes());
    }
}
