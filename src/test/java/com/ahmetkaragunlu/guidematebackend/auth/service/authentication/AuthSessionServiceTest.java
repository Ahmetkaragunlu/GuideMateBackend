package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.notification.service.device.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthSessionServiceTest {

    private static final String INSTALLATION_ID = "11111111-1111-4111-8111-111111111111";

    @Mock private RefreshSessionService refreshSessionService;
    @Mock private InstallationIdValidator installationIdValidator;
    @Mock private UserRepository userRepository;
    @Mock private DeviceRegistrationService deviceRegistrationService;
    @Mock private AuthResponseService authResponseService;
    @Mock private MessageSource messageSource;

    private AuthSessionService service;

    @BeforeEach
    void setUp() {
        service = new AuthSessionService(
                refreshSessionService,
                installationIdValidator,
                new EmailNormalizer(),
                userRepository,
                deviceRegistrationService,
                authResponseService,
                messageSource
        );
    }

    @Test
    void returnsRotatedSessionAsAuthResponse() {
        User user = mockUser();
        AuthResponse response = org.mockito.Mockito.mock(AuthResponse.class);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(refreshSessionService.rotate("refresh-token", INSTALLATION_ID))
                .thenReturn(RefreshSessionService.RefreshRotationResult.success(user, "new-refresh-token"));
        when(authResponseService.create(user, "new-refresh-token", "auth.login.success"))
                .thenReturn(response);

        assertThat(service.refreshToken("refresh-token", INSTALLATION_ID)).isSameAs(response);
    }

    @Test
    void propagatesRefreshRotationFailureWithoutCreatingResponse() {
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(refreshSessionService.rotate("refresh-token", INSTALLATION_ID))
                .thenReturn(RefreshSessionService.RefreshRotationResult.failure(ErrorCode.REFRESH_TOKEN_EXPIRED));

        assertThatThrownBy(() -> service.refreshToken("refresh-token", INSTALLATION_ID))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.REFRESH_TOKEN_EXPIRED));

        verify(authResponseService, never()).create(any(), any(), any());
    }

    @Test
    void logoutRevokesSessionAndDeactivatesOnlyCurrentInstallation() {
        UUID installationId = UUID.fromString(INSTALLATION_ID);
        User user = mockUser();
        when(user.getId()).thenReturn(42L);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(messageSource.getMessage(
                org.mockito.ArgumentMatchers.eq("auth.logout.success"),
                isNull(),
                any(Locale.class)
        )).thenReturn("logged out");

        assertThat(service.logout("refresh-token", " User@Example.com ", INSTALLATION_ID))
                .isEqualTo("logged out");

        verify(refreshSessionService).revoke("refresh-token", "user@example.com", INSTALLATION_ID);
        verify(deviceRegistrationService).deactivate(42L, installationId);
    }

    private User mockUser() {
        return org.mockito.Mockito.mock(User.class);
    }
}
