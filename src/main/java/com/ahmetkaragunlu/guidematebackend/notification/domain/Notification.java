package com.ahmetkaragunlu.guidematebackend.notification.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
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
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "notifications",
        indexes = {
                @Index(name = "idx_notification_recipient_created", columnList = "recipient_id, created_at"),
                @Index(name = "idx_notification_recipient_unread", columnList = "recipient_id, read_at"),
                @Index(
                        name = "idx_notification_push_retry",
                        columnList = "push_status, next_push_attempt_at, push_attempt_count"
                )
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_notification_deduplication",
                columnNames = {"recipient_id", "type", "deduplication_key"}
        )
)
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false, updatable = false)
    private User recipient;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, updatable = false, length = 64)
    private NotificationType type;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "actor_id", updatable = false)
    private User actor;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", nullable = false, updatable = false, columnDefinition = "jsonb")
    private String payloadJson;

    @Column(name = "read_at")
    private Instant readAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "push_status", nullable = false, length = 16)
    private NotificationPushStatus pushStatus;

    @Column(name = "last_push_attempt_at")
    private Instant lastPushAttemptAt;

    @Column(name = "deduplication_key", length = 160)
    private String deduplicationKey;

    @Column(name = "push_attempt_count", nullable = false)
    private int pushAttemptCount;

    @Column(name = "next_push_attempt_at")
    private Instant nextPushAttemptAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public Notification(
            User recipient,
            NotificationType type,
            User actor,
            String payloadJson,
            NotificationPushStatus pushStatus
    ) {
        this(recipient, type, actor, payloadJson, pushStatus, null);
    }

    public Notification(
            User recipient,
            NotificationType type,
            User actor,
            String payloadJson,
            NotificationPushStatus pushStatus,
            String deduplicationKey
    ) {
        this.recipient = Objects.requireNonNull(recipient);
        this.type = Objects.requireNonNull(type);
        this.actor = actor;
        this.payloadJson = Objects.requireNonNull(payloadJson);
        this.pushStatus = Objects.requireNonNull(pushStatus);
        this.deduplicationKey = deduplicationKey;
    }

    public boolean isRead() {
        return readAt != null;
    }

    public void markRead(Instant now) {
        if (readAt == null) {
            readAt = Objects.requireNonNull(now);
        }
    }

    public boolean canAttemptPush(Instant now, int maxAttempts) {
        return pushAttemptCount < maxAttempts
                && (nextPushAttemptAt == null || !nextPushAttemptAt.isAfter(now));
    }

    public void markPushAttempt(Instant now, Instant nextAttemptAt) {
        lastPushAttemptAt = Objects.requireNonNull(now);
        nextPushAttemptAt = Objects.requireNonNull(nextAttemptAt);
        pushAttemptCount++;
    }

    public void markPushSent() {
        pushStatus = NotificationPushStatus.SENT;
        nextPushAttemptAt = null;
    }

    public void markPushFailed() {
        pushStatus = NotificationPushStatus.FAILED;
    }

    public void markPushNotRequested() {
        pushStatus = NotificationPushStatus.NOT_REQUESTED;
        nextPushAttemptAt = null;
    }
}
