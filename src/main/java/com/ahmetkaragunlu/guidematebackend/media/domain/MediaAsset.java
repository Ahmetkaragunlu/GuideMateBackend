package com.ahmetkaragunlu.guidematebackend.media.domain;

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
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Getter
@Entity
@Table(
        name = "media_assets",
        indexes = {
                @Index(name = "idx_media_owner", columnList = "owner_user_id"),
                @Index(name = "idx_media_status_created", columnList = "status, created_at")
        }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MediaAsset extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_user_id", nullable = false)
    private User owner;

    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, length = 32)
    private MediaPurpose purpose;

    @Column(name = "storage_key", nullable = false, unique = true, length = 255)
    private String storageKey;

    @Column(name = "original_file_name", nullable = false, length = 255)
    private String originalFileName;

    @Column(name = "content_type", nullable = false, length = 64)
    private String contentType;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private MediaStatus status;

    private MediaAsset(
            User owner,
            MediaPurpose purpose,
            String storageKey,
            String originalFileName,
            String contentType,
            long sizeBytes
    ) {
        this.owner = Objects.requireNonNull(owner);
        this.purpose = Objects.requireNonNull(purpose);
        this.storageKey = Objects.requireNonNull(storageKey);
        this.originalFileName = Objects.requireNonNull(originalFileName);
        this.contentType = Objects.requireNonNull(contentType);
        this.sizeBytes = sizeBytes;
        this.status = MediaStatus.PENDING;
    }

    public static MediaAsset pending(
            User owner,
            MediaPurpose purpose,
            String storageKey,
            String originalFileName,
            String contentType,
            long sizeBytes
    ) {
        return new MediaAsset(owner, purpose, storageKey, originalFileName, contentType, sizeBytes);
    }

    public boolean isOwnedBy(Long userId) {
        return userId != null && userId.equals(owner.getId());
    }

    public boolean isReady() {
        return status == MediaStatus.READY;
    }

    public void markReady() {
        if (status != MediaStatus.PENDING) {
            throw new IllegalStateException("Only pending media can become ready");
        }
        status = MediaStatus.READY;
    }

    public void markDeleted() {
        status = MediaStatus.DELETED;
    }
}
