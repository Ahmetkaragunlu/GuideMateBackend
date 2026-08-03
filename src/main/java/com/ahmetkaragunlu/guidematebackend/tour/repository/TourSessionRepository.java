package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
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
public interface TourSessionRepository extends JpaRepository<TourSession, UUID> {

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    List<TourSession> findAllByTour_IdOrderByStartsAtAsc(UUID tourId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia", "tour.languageCodes"})
    @Query("SELECT session FROM TourSession session WHERE session.id = :sessionId AND session.tour.guide.id = :guideId")
    Optional<TourSession> findOwnedByIdForUpdate(
            @Param("sessionId") UUID sessionId,
            @Param("guideId") Long guideId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia", "tour.languageCodes"})
    @Query("SELECT session FROM TourSession session WHERE session.id = :sessionId")
    Optional<TourSession> findByIdForUpdate(@Param("sessionId") UUID sessionId);

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query("""
            SELECT session
            FROM TourSession session
            WHERE session.tour.guide.id = :guideId
              AND session.id <> :excludedSessionId
              AND session.startsAt < :candidateEnd
              AND session.status IN :manageableStatuses
              AND session.tour.approvalStatus NOT IN :excludedTourStatuses
            """)
    List<TourSession> findScheduleCandidates(
            @Param("guideId") Long guideId,
            @Param("excludedSessionId") UUID excludedSessionId,
            @Param("candidateEnd") Instant candidateEnd,
            @Param("manageableStatuses") Collection<TourSessionStatus> manageableStatuses,
            @Param("excludedTourStatuses") Collection<TourApprovalStatus> excludedTourStatuses
    );

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query("""
            SELECT session
            FROM TourSession session
            WHERE session.tour.guide.id = :guideId
              AND session.startsAt < :candidateEnd
              AND session.status IN :manageableStatuses
              AND session.tour.approvalStatus NOT IN :excludedTourStatuses
            """)
    List<TourSession> findScheduleCandidates(
            @Param("guideId") Long guideId,
            @Param("candidateEnd") Instant candidateEnd,
            @Param("manageableStatuses") Collection<TourSessionStatus> manageableStatuses,
            @Param("excludedTourStatuses") Collection<TourApprovalStatus> excludedTourStatuses
    );

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query(
            value = """
                    SELECT session FROM TourSession session
                    WHERE session.tour.guide.id = :guideId
                      AND session.tour.approvalStatus = :approvedStatus
                      AND session.status IN :manageableStatuses
                      AND session.startsAt > :now
                    ORDER BY session.startsAt ASC
                    """,
            countQuery = """
                    SELECT COUNT(session) FROM TourSession session
                    WHERE session.tour.guide.id = :guideId
                      AND session.tour.approvalStatus = :approvedStatus
                      AND session.status IN :manageableStatuses
                      AND session.startsAt > :now
                    """
    )
    Page<TourSession> findActiveGuideSessions(
            @Param("guideId") Long guideId,
            @Param("approvedStatus") TourApprovalStatus approvedStatus,
            @Param("manageableStatuses") Collection<TourSessionStatus> manageableStatuses,
            @Param("now") Instant now,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query(
            value = """
                    SELECT session FROM TourSession session
                    WHERE session.tour.guide.id = :guideId
                      AND (
                          session.tour.approvalStatus IN :reviewStatuses
                          OR EXISTS (
                              SELECT changeRequest.id
                              FROM TourChangeRequest changeRequest
                              WHERE changeRequest.tour = session.tour
                                AND changeRequest.status = :pendingChangeStatus
                          )
                      )
                      AND session.status IN :manageableStatuses
                    ORDER BY session.tour.submittedAt DESC, session.startsAt ASC
                    """,
            countQuery = """
                    SELECT COUNT(session) FROM TourSession session
                    WHERE session.tour.guide.id = :guideId
                      AND (
                          session.tour.approvalStatus IN :reviewStatuses
                          OR EXISTS (
                              SELECT changeRequest.id
                              FROM TourChangeRequest changeRequest
                              WHERE changeRequest.tour = session.tour
                                AND changeRequest.status = :pendingChangeStatus
                          )
                      )
                      AND session.status IN :manageableStatuses
                    """
    )
    Page<TourSession> findGuideReviewSessions(
            @Param("guideId") Long guideId,
            @Param("reviewStatuses") Collection<TourApprovalStatus> reviewStatuses,
            @Param("pendingChangeStatus") TourChangeRequestStatus pendingChangeStatus,
            @Param("manageableStatuses") Collection<TourSessionStatus> manageableStatuses,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query(
            value = """
                    SELECT session FROM TourSession session
                    WHERE session.tour.guide.id = :guideId
                      AND session.status IN :terminalStatuses
                    ORDER BY session.startsAt DESC
                    """,
            countQuery = """
                    SELECT COUNT(session) FROM TourSession session
                    WHERE session.tour.guide.id = :guideId
                      AND session.status IN :terminalStatuses
                    """
    )
    Page<TourSession> findPastGuideSessions(
            @Param("guideId") Long guideId,
            @Param("terminalStatuses") Collection<TourSessionStatus> terminalStatuses,
            Pageable pageable
    );

    @Query("""
            SELECT COUNT(session) FROM TourSession session
            WHERE session.tour.guide.id = :guideId
              AND session.tour.approvalStatus = :approvedStatus
              AND session.status = :openStatus
              AND session.startsAt > :now
            """)
    long countActiveSessions(
            @Param("guideId") Long guideId,
            @Param("approvedStatus") TourApprovalStatus approvedStatus,
            @Param("openStatus") TourSessionStatus openStatus,
            @Param("now") Instant now
    );

    long countByTour_Guide_IdAndStatus(Long guideId, TourSessionStatus status);

    @Query("""
            SELECT session.tour.guide.id AS guideId, COUNT(session) AS completedSessionCount
            FROM TourSession session
            WHERE session.tour.guide.id IN :guideIds
              AND session.status = :status
            GROUP BY session.tour.guide.id
            """)
    List<GuideCompletedSessionCount> countCompletedSessionsByGuideIds(
            @Param("guideIds") Collection<Long> guideIds,
            @Param("status") TourSessionStatus status
    );

    List<TourSession> findByStatusInAndStartsAtBefore(
            Collection<TourSessionStatus> statuses,
            Instant startsBefore
    );

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query("""
            SELECT session FROM TourSession session
            WHERE session.id = :sessionId
              AND session.tour.approvalStatus = :approvalStatus
            """)
    Optional<TourSession> findPublicSession(
            @Param("sessionId") UUID sessionId,
            @Param("approvalStatus") TourApprovalStatus approvalStatus
    );

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia"})
    @Query("""
            SELECT session FROM TourSession session
            WHERE session.tour.id = :tourId
              AND session.tour.approvalStatus = :approvalStatus
              AND session.status <> :cancelledStatus
              AND session.startsAt > :now
            ORDER BY session.startsAt ASC
            """)
    List<TourSession> findFuturePublicSessions(
            @Param("tourId") UUID tourId,
            @Param("approvalStatus") TourApprovalStatus approvalStatus,
            @Param("cancelledStatus") TourSessionStatus cancelledStatus,
            @Param("now") Instant now,
            Pageable pageable
    );
}
