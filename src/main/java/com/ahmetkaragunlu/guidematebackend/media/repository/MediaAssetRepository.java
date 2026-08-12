package com.ahmetkaragunlu.guidematebackend.media.repository;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Pageable;
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
public interface MediaAssetRepository extends JpaRepository<MediaAsset, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT media FROM MediaAsset media WHERE media.id = :id")
    Optional<MediaAsset> findByIdForUpdate(@Param("id") UUID id);

    List<MediaAsset> findByStatusInAndCreatedAtBeforeOrderByCreatedAt(
            Collection<MediaStatus> statuses,
            Instant createdBefore,
            Pageable pageable
    );

    List<MediaAsset> findByStatusOrderByCreatedAt(MediaStatus status, Pageable pageable);
}
