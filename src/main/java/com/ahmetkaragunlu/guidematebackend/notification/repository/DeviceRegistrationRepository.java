package com.ahmetkaragunlu.guidematebackend.notification.repository;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRegistrationRepository extends JpaRepository<DeviceRegistration, UUID> {

    Optional<DeviceRegistration> findByInstallationId(UUID installationId);

    Optional<DeviceRegistration> findByFirebaseInstallationId(String firebaseInstallationId);

    List<DeviceRegistration> findAllByUser_IdAndActiveTrue(Long userId);
}
