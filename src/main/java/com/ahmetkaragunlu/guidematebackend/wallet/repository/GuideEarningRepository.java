package com.ahmetkaragunlu.guidematebackend.wallet.repository;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarningStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface GuideEarningRepository extends JpaRepository<GuideEarning, UUID> {

    Optional<GuideEarning> findByReservation_Id(UUID reservationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT earning FROM GuideEarning earning WHERE earning.reservation.id = :reservationId")
    Optional<GuideEarning> findByReservationIdForUpdate(@Param("reservationId") UUID reservationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT earning FROM GuideEarning earning WHERE earning.id = :earningId")
    Optional<GuideEarning> findByIdForUpdate(@Param("earningId") UUID earningId);

    @Query("""
            SELECT earning.id FROM GuideEarning earning
            WHERE earning.status = :status
              AND earning.availableAt <= :now
            ORDER BY earning.availableAt, earning.id
            """)
    List<UUID> findAvailabilityCandidateIds(
            @Param("status") GuideEarningStatus status,
            @Param("now") Instant now,
            Pageable pageable
    );

    @Query("SELECT earning FROM GuideEarning earning "
            + "WHERE earning.reservation.session.tour.guide.id = :guideId "
            + "AND earning.createdAt >= :from AND earning.createdAt < :until "
            + "AND earning.status <> :reversed ORDER BY earning.createdAt")
    List<GuideEarning> findGuideEarningsInPeriod(
            @Param("guideId") Long guideId,
            @Param("from") Instant from,
            @Param("until") Instant until,
            @Param("reversed") GuideEarningStatus reversed
    );

    @Query(
            value = "SELECT earning FROM GuideEarning earning "
                    + "WHERE earning.reservation.session.tour.guide.id = :guideId "
                    + "AND earning.createdAt >= :from AND earning.createdAt < :until "
                    + "ORDER BY earning.createdAt DESC",
            countQuery = "SELECT COUNT(earning) FROM GuideEarning earning "
                    + "WHERE earning.reservation.session.tour.guide.id = :guideId "
                    + "AND earning.createdAt >= :from AND earning.createdAt < :until"
    )
    Page<GuideEarning> findGuideEarningsPage(
            @Param("guideId") Long guideId,
            @Param("from") Instant from,
            @Param("until") Instant until,
            Pageable pageable
    );
}
