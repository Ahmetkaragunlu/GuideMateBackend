package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.GoogleTokenVerifier;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.InstallationIdValidator;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GoogleLoginServiceTest {

    private static final String INSTALLATION_ID = "11111111-1111-4111-8111-111111111111";
    private static final String CLIENT_IP = "203.0.113.10";

    @Mock private UserRepository userRepository;
    @Mock private InstallationIdValidator installationIdValidator;
    @Mock private GoogleTokenVerifier googleTokenVerifier;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private LoginSessionService loginSessionService;

    private GoogleLoginService service;

    @BeforeEach
    void setUp() {
        service = new GoogleLoginService(
                userRepository,
                new EmailNormalizer(),
                installationIdValidator,
                googleTokenVerifier,
                rateLimitService,
                accountStatusPolicy,
                loginSessionService
        );
    }

    @Test
    void rateLimitStopsLoginBeforeExternalTokenVerification() {
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        doThrow(new RateLimitException(30))
                .when(rateLimitService)
                .acquireGoogleLoginPermit(INSTALLATION_ID, CLIENT_IP);

        assertThatThrownBy(() -> service.login(
                new GoogleLoginRequest("google-id-token"),
                INSTALLATION_ID,
                CLIENT_IP
        )).isInstanceOf(RateLimitException.class);

        verifyNoInteractions(googleTokenVerifier, userRepository);
    }

    @Test
    void linksExistingActiveAccountOnFirstGoogleLogin() {
        User user = activeUser();
        AuthResponse expected = org.mockito.Mockito.mock(AuthResponse.class);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleTokenVerifier.GoogleIdentity("google-subject", " USER@example.com "));
        when(userRepository.findByGoogleSubjectWithRole("google-subject")).thenReturn(Optional.empty());
        when(userRepository.findByEmailForUpdate("user@example.com")).thenReturn(Optional.of(user));
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.empty());
        when(loginSessionService.complete(user, INSTALLATION_ID)).thenReturn(expected);

        AuthResponse response = service.login(
                new GoogleLoginRequest("google-id-token"),
                INSTALLATION_ID,
                CLIENT_IP
        );

        assertThat(user.getGoogleSubject()).isEqualTo("google-subject");
        assertThat(response).isSameAs(expected);
        verify(userRepository).saveAndFlush(user);
    }

    @Test
    void rejectsSubjectAlreadyBoundToAnotherAccount() {
        User requested = activeUser();
        User linked = org.mockito.Mockito.mock(User.class);
        when(linked.getId()).thenReturn(99L);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleTokenVerifier.GoogleIdentity("google-subject", requested.getEmail()));
        when(userRepository.findByGoogleSubjectWithRole("google-subject")).thenReturn(Optional.empty());
        when(userRepository.findByEmailForUpdate(requested.getEmail())).thenReturn(Optional.of(requested));
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.of(linked));

        assertThatThrownBy(() -> service.login(
                new GoogleLoginRequest("google-id-token"),
                INSTALLATION_ID,
                CLIENT_IP
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_ACCOUNT_MISMATCH));
        verify(loginSessionService, never()).complete(any(), anyString());
    }

    private User activeUser() {
        User user = new User("Test", "User", "user@example.com", "hash");
        user.activate();
        return user;
    }
}
