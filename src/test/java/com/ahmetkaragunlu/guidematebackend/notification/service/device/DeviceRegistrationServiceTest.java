package com.ahmetkaragunlu.guidematebackend.notification.service.device;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import com.ahmetkaragunlu.guidematebackend.notification.dto.RegisterDeviceRegistrationRequest;
import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceRegistrationServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");
    private static final UUID INSTALLATION_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");

    @Mock private DeviceRegistrationRepository registrationRepository;
    @Mock private UserRepository userRepository;

    private DeviceRegistrationService service;

    @BeforeEach
    void setUp() {
        service = new DeviceRegistrationService(
                registrationRepository,
                userRepository,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void createsActiveRegistrationForCurrentUser() {
        User current = org.mockito.Mockito.mock(User.class);
        User reference = org.mockito.Mockito.mock(User.class);
        when(current.getId()).thenReturn(42L);
        when(userRepository.getReferenceById(42L)).thenReturn(reference);
        when(registrationRepository.findByInstallationId(INSTALLATION_ID)).thenReturn(Optional.empty());
        when(registrationRepository.findByFirebaseInstallationId("firebase-id")).thenReturn(Optional.empty());
        when(registrationRepository.save(any(DeviceRegistration.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.register(
                current,
                new RegisterDeviceRegistrationRequest(INSTALLATION_ID, " firebase-id ")
        );

        assertThat(response.installationId()).isEqualTo(INSTALLATION_ID);
        assertThat(response.active()).isTrue();
    }

    @Test
    void mergesConflictingFirebaseRegistrationIntoInstallationRecord() {
        User current = org.mockito.Mockito.mock(User.class);
        User reference = org.mockito.Mockito.mock(User.class);
        DeviceRegistration installation = org.mockito.Mockito.mock(DeviceRegistration.class);
        DeviceRegistration duplicateFirebase = org.mockito.Mockito.mock(DeviceRegistration.class);
        when(current.getId()).thenReturn(42L);
        when(userRepository.getReferenceById(42L)).thenReturn(reference);
        when(registrationRepository.findByInstallationId(INSTALLATION_ID)).thenReturn(Optional.of(installation));
        when(registrationRepository.findByFirebaseInstallationId("firebase-id"))
                .thenReturn(Optional.of(duplicateFirebase));
        when(registrationRepository.save(installation)).thenReturn(installation);
        when(installation.getInstallationId()).thenReturn(INSTALLATION_ID);
        when(installation.isActive()).thenReturn(true);
        when(installation.getLastSeenAt()).thenReturn(NOW);

        service.register(current, new RegisterDeviceRegistrationRequest(INSTALLATION_ID, "firebase-id"));

        verify(registrationRepository).delete(duplicateFirebase);
        verify(registrationRepository).flush();
        verify(installation).register(reference, INSTALLATION_ID, "firebase-id", NOW);
    }

    @Test
    void deactivatesRegistrationOnlyForItsOwner() {
        User owner = org.mockito.Mockito.mock(User.class);
        DeviceRegistration registration = org.mockito.Mockito.mock(DeviceRegistration.class);
        when(owner.getId()).thenReturn(42L);
        when(registration.getUser()).thenReturn(owner);
        when(registrationRepository.findByInstallationId(INSTALLATION_ID)).thenReturn(Optional.of(registration));

        service.deactivate(7L, INSTALLATION_ID);
        verify(registration, never()).deactivate();

        service.deactivate(42L, INSTALLATION_ID);
        verify(registration).deactivate();
    }

    @Test
    void deletesOnlyInactiveExpiredRegistration() {
        UUID registrationId = UUID.randomUUID();
        DeviceRegistration registration = org.mockito.Mockito.mock(DeviceRegistration.class);
        when(registration.isActive()).thenReturn(false);
        when(registration.getLastSeenAt()).thenReturn(NOW.minusSeconds(3600));
        when(registrationRepository.findByIdForUpdate(registrationId)).thenReturn(Optional.of(registration));

        service.deleteIfExpired(registrationId, NOW.minusSeconds(1800));

        verify(registrationRepository).delete(registration);
    }
}
