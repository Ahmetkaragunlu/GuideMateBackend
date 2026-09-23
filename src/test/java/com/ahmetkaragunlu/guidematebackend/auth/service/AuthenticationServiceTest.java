package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.SelectableRole;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.notification.service.device.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    private static final String INSTALLATION_ID = "11111111-1111-4111-8111-111111111111";
    private static final String CLIENT_IP = "203.0.113.10";

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private InstallationIdValidator installationIdValidator;
    @Mock private GoogleTokenVerifier googleTokenVerifier;
    @Mock private RefreshSessionService refreshSessionService;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private MessageSource messageSource;
    @Mock private DeviceRegistrationService deviceRegistrationService;
    @Mock private MediaReferenceMapper mediaReferenceMapper;

    private AuthenticationService service;

    @BeforeEach
    void setUp() {
        service = new AuthenticationService(
                userRepository,
                roleRepository,
                authenticationManager,
                passwordEncoder,
                jwtService,
                new EmailNormalizer(),
                installationIdValidator,
                googleTokenVerifier,
                refreshSessionService,
                rateLimitService,
                accountStatusPolicy,
                messageSource,
                deviceRegistrationService,
                mediaReferenceMapper
        );
    }

    @Test
    void rateLimitStopsGoogleLoginBeforeExternalTokenVerification() {
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        doThrow(new RateLimitException(30))
                .when(rateLimitService)
                .acquireGoogleLoginPermit(INSTALLATION_ID, CLIENT_IP);

        assertThatThrownBy(() -> service.googleLogin(
                new GoogleLoginRequest("google-id-token"),
                INSTALLATION_ID,
                CLIENT_IP
        )).isInstanceOf(RateLimitException.class);

        verifyNoInteractions(googleTokenVerifier, userRepository);
    }

    @Test
    void linksExistingActiveAccountOnFirstGoogleLogin() {
        User user = activeUser();
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleTokenVerifier.GoogleIdentity("google-subject", " USER@example.com "));
        when(userRepository.findByGoogleSubjectWithRole("google-subject")).thenReturn(Optional.empty());
        when(userRepository.findByEmailForUpdate("user@example.com")).thenReturn(Optional.of(user));
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.empty());
        when(refreshSessionService.createSession(user, INSTALLATION_ID)).thenReturn("refresh-token");
        when(jwtService.generateToken(user)).thenReturn("access-token");
        when(messageSource.getMessage(anyString(), isNull(), any(Locale.class))).thenReturn("success");

        var response = service.googleLogin(
                new GoogleLoginRequest("google-id-token"),
                INSTALLATION_ID,
                CLIENT_IP
        );

        assertThat(user.getGoogleSubject()).isEqualTo("google-subject");
        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        verify(userRepository).saveAndFlush(user);
    }

    @Test
    void rejectsGoogleSubjectAlreadyBoundToAnotherAccount() {
        User requested = activeUser();
        User linked = org.mockito.Mockito.mock(User.class);
        when(linked.getId()).thenReturn(99L);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleTokenVerifier.GoogleIdentity("google-subject", requested.getEmail()));
        when(userRepository.findByGoogleSubjectWithRole("google-subject")).thenReturn(Optional.empty());
        when(userRepository.findByEmailForUpdate(requested.getEmail())).thenReturn(Optional.of(requested));
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.of(linked));

        assertThatThrownBy(() -> service.googleLogin(
                new GoogleLoginRequest("google-id-token"),
                INSTALLATION_ID,
                CLIENT_IP
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_ACCOUNT_MISMATCH));
        verify(refreshSessionService, never()).createSession(any(), anyString());
    }

    @Test
    void selectsRoleOnlyForAccountWithoutExistingRole() {
        User user = activeUser();
        Role guideRole = org.mockito.Mockito.mock(Role.class);
        when(guideRole.getName()).thenReturn(RoleType.ROLE_GUIDE.name());
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(roleRepository.findByName(RoleType.ROLE_GUIDE.name())).thenReturn(Optional.of(guideRole));
        when(jwtService.generateToken(user)).thenReturn("access-token");
        when(messageSource.getMessage(anyString(), isNull(), any(Locale.class))).thenReturn("selected");

        var response = service.selectRole(
                new RoleSelectionRequest(SelectableRole.ROLE_GUIDE),
                user.getEmail()
        );

        assertThat(user.hasRole(RoleType.ROLE_GUIDE)).isTrue();
        assertThat(response.role()).isEqualTo(RoleType.ROLE_GUIDE.name());
    }

    @Test
    void logoutRevokesSessionAndDeactivatesOnlyCurrentInstallation() {
        UUID installationId = UUID.fromString(INSTALLATION_ID);
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(messageSource.getMessage(anyString(), isNull(), any(Locale.class))).thenReturn("logged out");

        assertThat(service.logout("refresh-token", " User@Example.com ", INSTALLATION_ID))
                .isEqualTo("logged out");

        verify(refreshSessionService).revoke("refresh-token", "user@example.com", INSTALLATION_ID);
        verify(deviceRegistrationService).deactivate(42L, installationId);
    }

    private User activeUser() {
        User user = new User("Test", "User", "user@example.com", "hash");
        user.activate();
        return user;
    }
}
