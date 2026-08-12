package com.ahmetkaragunlu.guidematebackend.reservation.repository;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ReservationRepository extends JpaRepository<Reservation, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"session", "session.tour", "tourist"})
    @Query("SELECT reservation FROM Reservation reservation WHERE reservation.id = :reservationId")
    Optional<Reservation> findByIdForUpdate(@Param("reservationId") UUID reservationId);

    @EntityGraph(attributePaths = {"session", "session.tour", "tourist"})
    @Query("SELECT reservation FROM Reservation reservation WHERE reservation.id = :reservationId AND reservation.tourist.id = :touristId")
    Optional<Reservation> findOwnedDetails(
            @Param("reservationId") UUID reservationId,
            @Param("touristId") Long touristId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"session", "session.tour", "tourist"})
    @Query("SELECT reservation FROM Reservation reservation WHERE reservation.id = :reservationId AND reservation.tourist.id = :touristId")
    Optional<Reservation> findOwnedByIdForUpdate(
            @Param("reservationId") UUID reservationId,
            @Param("touristId") Long touristId
    );

    @EntityGraph(attributePaths = {"session", "session.tour", "tourist"})
    @Query(
            value = """
                    SELECT reservation FROM Reservation reservation
                    WHERE reservation.tourist.id = :touristId
                      AND reservation.status = :confirmedStatus
                    ORDER BY reservation.session.startsAt ASC
                    """,
            countQuery = """
                    SELECT COUNT(reservation) FROM Reservation reservation
                    WHERE reservation.tourist.id = :touristId
                      AND reservation.status = :confirmedStatus
                    """
    )
    Page<Reservation> findUpcomingTrips(
            @Param("touristId") Long touristId,
            @Param("confirmedStatus") ReservationStatus confirmedStatus,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"session", "session.tour", "tourist"})
    @Query(
            value = """
                    SELECT reservation FROM Reservation reservation
                    WHERE reservation.tourist.id = :touristId
                      AND reservation.status IN :pastStatuses
                    ORDER BY reservation.session.startsAt DESC
                    """,
            countQuery = """
                    SELECT COUNT(reservation) FROM Reservation reservation
                    WHERE reservation.tourist.id = :touristId
                      AND reservation.status IN :pastStatuses
                    """
    )
    Page<Reservation> findPastTrips(
            @Param("touristId") Long touristId,
            @Param("pastStatuses") Collection<ReservationStatus> pastStatuses,
            Pageable pageable
    );

    Optional<Reservation> findByTourist_IdAndIdempotencyKey(Long touristId, String idempotencyKey);

    @EntityGraph(attributePaths = {"session", "session.tour", "tourist"})
    Optional<Reservation> findByTourist_IdAndCancellationIdempotencyKey(
            Long touristId,
            String cancellationIdempotencyKey
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT reservation FROM Reservation reservation
            WHERE reservation.session.id = :sessionId
              AND reservation.tourist.id = :touristId
              AND reservation.status IN :activeStatuses
            """)
    Optional<Reservation> findActiveBySessionAndTouristForUpdate(
            @Param("sessionId") UUID sessionId,
            @Param("touristId") Long touristId,
            @Param("activeStatuses") Collection<ReservationStatus> activeStatuses
    );

    @Query("""
            SELECT reservation.session.id AS sessionId,
                   COALESCE(SUM(reservation.participantCount), 0) AS participantCount
            FROM Reservation reservation
            WHERE reservation.session.id IN :sessionIds
              AND (
                  reservation.status IN :occupiedStatuses
                  OR (reservation.status = :pendingStatus AND reservation.holdExpiresAt > :now)
              )
            GROUP BY reservation.session.id
            """)
    List<SessionOccupancy> sumOccupancyBySessionIds(
            @Param("sessionIds") Collection<UUID> sessionIds,
            @Param("occupiedStatuses") Collection<ReservationStatus> occupiedStatuses,
            @Param("pendingStatus") ReservationStatus pendingStatus,
            @Param("now") Instant now
    );

    @Query("""
            SELECT COALESCE(SUM(reservation.participantCount), 0)
            FROM Reservation reservation
            WHERE reservation.session.id = :sessionId
              AND (
                  reservation.status IN :occupiedStatuses
                  OR (reservation.status = :pendingStatus AND reservation.holdExpiresAt > :now)
              )
            """)
    long sumOccupancyBySessionId(
            @Param("sessionId") UUID sessionId,
            @Param("occupiedStatuses") Collection<ReservationStatus> occupiedStatuses,
            @Param("pendingStatus") ReservationStatus pendingStatus,
            @Param("now") Instant now
    );

    @Query("""
            SELECT CASE WHEN COUNT(reservation) > 0 THEN TRUE ELSE FALSE END
            FROM Reservation reservation
            WHERE reservation.session.id = :sessionId
              AND (
                  reservation.status = :confirmedStatus
                  OR (reservation.status = :pendingStatus AND reservation.holdExpiresAt > :now)
              )
            """)
    boolean existsActiveReservation(
            @Param("sessionId") UUID sessionId,
            @Param("confirmedStatus") ReservationStatus confirmedStatus,
            @Param("pendingStatus") ReservationStatus pendingStatus,
            @Param("now") Instant now
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT reservation FROM Reservation reservation
            WHERE reservation.session.id = :sessionId
              AND reservation.status IN :statuses
            """)
    List<Reservation> findBySessionIdAndStatusInForUpdate(
            @Param("sessionId") UUID sessionId,
            @Param("statuses") Collection<ReservationStatus> statuses
    );

    @Query("""
            SELECT reservation.session.tour.guide.id AS guideId,
                   COALESCE(SUM(reservation.participantCount), 0) AS participantCount
            FROM Reservation reservation
            WHERE reservation.session.tour.guide.id IN :guideIds
              AND reservation.status = :completedStatus
            GROUP BY reservation.session.tour.guide.id
            """)
    List<GuideParticipantSummary> sumCompletedParticipantsByGuideIds(
            @Param("guideIds") Collection<Long> guideIds,
            @Param("completedStatus") ReservationStatus completedStatus
    );

    @Query(value = """
            SELECT EXISTS (
                SELECT 1 FROM reservations reservation
                WHERE reservation.purchase_snapshot ->> 'coverMediaId' = CAST(:mediaAssetId AS VARCHAR)
                   OR reservation.purchase_snapshot ->> 'guideAvatarMediaId' = CAST(:mediaAssetId AS VARCHAR)
            )
            """, nativeQuery = true)
    boolean existsSnapshotMediaReference(@Param("mediaAssetId") UUID mediaAssetId);

    @Query(value = """
            SELECT EXISTS (
                SELECT 1 FROM reservations reservation
                WHERE reservation.tourist_id = :touristId
                  AND (
                      reservation.purchase_snapshot ->> 'coverMediaId' = CAST(:mediaAssetId AS VARCHAR)
                      OR reservation.purchase_snapshot ->> 'guideAvatarMediaId' = CAST(:mediaAssetId AS VARCHAR)
                  )
            )
            """, nativeQuery = true)
    boolean existsSnapshotMediaReferenceForTourist(
            @Param("mediaAssetId") UUID mediaAssetId,
            @Param("touristId") Long touristId
    );

    @Query("""
            SELECT reservation.id FROM Reservation reservation
            WHERE reservation.status = :status
              AND reservation.holdExpiresAt <= :now
            ORDER BY reservation.holdExpiresAt, reservation.id
            """)
    List<UUID> findExpiredHoldCandidateIds(
            @Param("status") ReservationStatus status,
            @Param("now") Instant now,
            Pageable pageable
    );

    @Query("""
            SELECT reservation.id FROM Reservation reservation
            WHERE reservation.status = :status
              AND reservation.upcomingReminderSentAt IS NULL
              AND reservation.session.startsAt > :now
              AND reservation.session.startsAt <= :until
            ORDER BY reservation.session.startsAt, reservation.id
            """)
    List<UUID> findUpcomingReminderCandidateIds(
            @Param("status") ReservationStatus status,
            @Param("now") Instant now,
            @Param("until") Instant until,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"session", "session.tour", "session.tour.guide", "tourist"})
    @Query("SELECT reservation FROM Reservation reservation WHERE reservation.id = :reservationId")
    Optional<Reservation> findReminderDetails(@Param("reservationId") UUID reservationId);
}
