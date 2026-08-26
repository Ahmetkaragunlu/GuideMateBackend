package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TourRepository extends JpaRepository<Tour, UUID> {

    @EntityGraph(attributePaths = {"guide", "guide.role", "coverMedia", "languageCodes"})
    @Query("SELECT tour FROM Tour tour WHERE tour.id = :tourId AND tour.guide.id = :guideId")
    Optional<Tour> findOwnedDetails(@Param("tourId") UUID tourId, @Param("guideId") Long guideId);

    @EntityGraph(attributePaths = {"guide", "guide.role", "coverMedia", "languageCodes"})
    @Query("SELECT tour FROM Tour tour WHERE tour.id = :tourId")
    Optional<Tour> findDetailsById(@Param("tourId") UUID tourId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"guide", "coverMedia", "languageCodes"})
    @Query("SELECT tour FROM Tour tour WHERE tour.id = :tourId AND tour.guide.id = :guideId")
    Optional<Tour> findOwnedByIdForUpdate(@Param("tourId") UUID tourId, @Param("guideId") Long guideId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"guide", "coverMedia", "languageCodes"})
    @Query("SELECT tour FROM Tour tour WHERE tour.id = :tourId")
    Optional<Tour> findByIdForUpdate(@Param("tourId") UUID tourId);

    long countByGuide_IdAndApprovalStatus(Long guideId, TourApprovalStatus approvalStatus);

    boolean existsByCoverMedia_Id(UUID mediaAssetId);

    @Query("""
            SELECT CASE WHEN COUNT(tour) > 0 THEN true ELSE false END
            FROM Tour tour
            JOIN tour.guide guide
            JOIN guide.role role
            WHERE tour.coverMedia.id = :mediaAssetId
              AND tour.approvalStatus = :approvalStatus
              AND guide.accountStatus = :accountStatus
              AND role.name = :roleName
            """)
    boolean existsPublicCoverReference(
            @Param("mediaAssetId") UUID mediaAssetId,
            @Param("approvalStatus") TourApprovalStatus approvalStatus,
            @Param("accountStatus") AccountStatus accountStatus,
            @Param("roleName") String roleName
    );
}
