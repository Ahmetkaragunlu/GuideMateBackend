package com.ahmetkaragunlu.guidematebackend.notification.repository;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRegistrationRepository extends JpaRepository<DeviceRegistration, UUID> {

    Optional<DeviceRegistration> findByInstallationId(UUID installationId);

    Optional<DeviceRegistration> findByFirebaseInstallationId(String firebaseInstallationId);

    List<DeviceRegistration> findAllByUser_IdAndActiveTrue(Long userId);

    @Query("""
            SELECT registration.id FROM DeviceRegistration registration
            WHERE registration.active = :active
              AND registration.lastSeenAt <= :lastSeenBefore
            ORDER BY registration.lastSeenAt, registration.id
            """)
    List<UUID> findCleanupCandidateIds(
            @Param("active") boolean active,
            @Param("lastSeenBefore") Instant lastSeenBefore,
            Pageable pageable
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT registration FROM DeviceRegistration registration WHERE registration.id = :id")
    Optional<DeviceRegistration> findByIdForUpdate(@Param("id") UUID id);
}
