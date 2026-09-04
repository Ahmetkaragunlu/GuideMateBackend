package com.ahmetkaragunlu.guidematebackend.notification.repository;

import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface NotificationRepository extends JpaRepository<Notification, UUID> {

    @EntityGraph(attributePaths = "actor")
    Page<Notification> findByRecipient_IdOrderByCreatedAtDescIdDesc(Long recipientId, Pageable pageable);

    long countByRecipient_IdAndReadAtIsNull(Long recipientId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT notification FROM Notification notification WHERE notification.id = :id")
    Optional<Notification> findByIdForUpdate(@Param("id") UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT notification FROM Notification notification
            WHERE notification.id = :id AND notification.recipient.id = :recipientId
            """)
    Optional<Notification> findOwnedByIdForUpdate(
            @Param("id") UUID id,
            @Param("recipientId") Long recipientId
    );

    Optional<Notification> findByRecipient_IdAndTypeAndDeduplicationKey(
            Long recipientId,
            NotificationType type,
            String deduplicationKey
    );

    @Query("""
            SELECT notification.id FROM Notification notification
            WHERE notification.pushStatus IN :statuses
              AND notification.pushAttemptCount < :maxAttempts
              AND (
                  notification.nextPushAttemptAt IS NULL
                  OR notification.nextPushAttemptAt <= :now
              )
            ORDER BY notification.createdAt, notification.id
            """)
    List<UUID> findPushRetryCandidateIds(
            @Param("statuses") Collection<NotificationPushStatus> statuses,
            @Param("now") Instant now,
            @Param("maxAttempts") int maxAttempts,
            Pageable pageable
    );

    @Modifying
    @Query("""
            UPDATE Notification notification
            SET notification.readAt = :readAt
            WHERE notification.recipient.id = :recipientId AND notification.readAt IS NULL
            """)
    int markAllRead(@Param("recipientId") Long recipientId, @Param("readAt") Instant readAt);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE notifications
            SET read_at = :readAt
            WHERE recipient_id = :recipientId
              AND read_at IS NULL
              AND jsonb_extract_path_text(payload, :payloadKey) = :targetId
            """, nativeQuery = true)
    int markRelatedRead(
            @Param("recipientId") Long recipientId,
            @Param("payloadKey") String payloadKey,
            @Param("targetId") String targetId,
            @Param("readAt") Instant readAt
    );
}
