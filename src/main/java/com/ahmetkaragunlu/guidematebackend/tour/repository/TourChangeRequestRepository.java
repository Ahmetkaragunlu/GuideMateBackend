package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface TourChangeRequestRepository extends JpaRepository<TourChangeRequest, UUID> {

    boolean existsByTour_IdAndStatus(UUID tourId, TourChangeRequestStatus status);

    long countByTour_Guide_IdAndStatus(Long guideId, TourChangeRequestStatus status);

    boolean existsByProposedCoverMedia_IdAndStatus(UUID mediaAssetId, TourChangeRequestStatus status);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia", "tour.languageCodes", "proposedCoverMedia", "submittedBy"})
    @Query("SELECT request FROM TourChangeRequest request WHERE request.id = :requestId")
    Optional<TourChangeRequest> findByIdForUpdate(@Param("requestId") UUID requestId);

    @EntityGraph(attributePaths = {"tour", "tour.guide", "tour.coverMedia", "tour.languageCodes", "proposedCoverMedia", "submittedBy"})
    @Query("SELECT request FROM TourChangeRequest request WHERE request.id = :requestId")
    Optional<TourChangeRequest> findDetailsById(@Param("requestId") UUID requestId);
}
