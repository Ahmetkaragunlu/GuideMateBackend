package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import com.ahmetkaragunlu.guidematebackend.notification.dto.DeviceRegistrationResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.RegisterDeviceRegistrationRequest;
import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceRegistrationService {

    private final DeviceRegistrationRepository registrationRepository;
    private final UserRepository userRepository;
    private final Clock clock;

    @Transactional
    public DeviceRegistrationResponse register(User currentUser, RegisterDeviceRegistrationRequest request) {
        String firebaseInstallationId = request.firebaseInstallationId().trim();
        DeviceRegistration installationRegistration = registrationRepository
                .findByInstallationId(request.installationId())
                .orElse(null);
        DeviceRegistration firebaseRegistration = registrationRepository
                .findByFirebaseInstallationId(firebaseInstallationId)
                .orElse(null);

        if (installationRegistration != null
                && firebaseRegistration != null
                && installationRegistration != firebaseRegistration) {
            registrationRepository.delete(firebaseRegistration);
            registrationRepository.flush();
        }

        DeviceRegistration registration = installationRegistration != null
                ? installationRegistration
                : firebaseRegistration;
        User userReference = userRepository.getReferenceById(currentUser.getId());
        if (registration == null) {
            registration = new DeviceRegistration(
                    userReference,
                    request.installationId(),
                    firebaseInstallationId,
                    clock.instant()
            );
        } else {
            registration.register(
                    userReference,
                    request.installationId(),
                    firebaseInstallationId,
                    clock.instant()
            );
        }
        return toResponse(registrationRepository.save(registration));
    }

    @Transactional
    public void deactivate(Long userId, UUID installationId) {
        registrationRepository.findByInstallationId(installationId)
                .filter(registration -> registration.getUser().getId().equals(userId))
                .ifPresent(DeviceRegistration::deactivate);
    }

    @Transactional
    public void deactivateIfInactive(UUID registrationId, Instant lastSeenBefore) {
        registrationRepository.findByIdForUpdate(registrationId)
                .filter(DeviceRegistration::isActive)
                .filter(registration -> !registration.getLastSeenAt().isAfter(lastSeenBefore))
                .ifPresent(DeviceRegistration::deactivate);
    }

    @Transactional
    public void deleteIfExpired(UUID registrationId, Instant lastSeenBefore) {
        registrationRepository.findByIdForUpdate(registrationId)
                .filter(registration -> !registration.isActive())
                .filter(registration -> !registration.getLastSeenAt().isAfter(lastSeenBefore))
                .ifPresent(registrationRepository::delete);
    }

    private DeviceRegistrationResponse toResponse(DeviceRegistration registration) {
        return new DeviceRegistrationResponse(
                registration.getId(),
                registration.getInstallationId(),
                registration.getPlatform(),
                registration.isActive(),
                registration.getLastSeenAt()
        );
    }
}
