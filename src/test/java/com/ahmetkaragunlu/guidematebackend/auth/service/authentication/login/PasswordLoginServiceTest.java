package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.InstallationIdValidator;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordLoginServiceTest {

    private static final String INSTALLATION_ID = "11111111-1111-4111-8111-111111111111";
    private static final String CLIENT_IP = "203.0.113.10";

    @Mock private UserRepository userRepository;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private InstallationIdValidator installationIdValidator;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private LoginSessionService loginSessionService;

    private PasswordLoginService service;

    @BeforeEach
    void setUp() {
        service = new PasswordLoginService(
                userRepository,
                authenticationManager,
                passwordEncoder,
                new EmailNormalizer(),
                installationIdValidator,
                rateLimitService,
                accountStatusPolicy,
                loginSessionService
        );
    }

    @Test
    void createsSessionAfterSuccessfulAuthentication() {
        User user = org.mockito.Mockito.mock(User.class);
        AuthResponse expected = org.mockito.Mockito.mock(AuthResponse.class);
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(userRepository.findByEmailWithRole("user@example.com")).thenReturn(Optional.of(user));
        when(loginSessionService.complete(user, INSTALLATION_ID)).thenReturn(expected);

        AuthResponse response = service.login(
                new LoginRequest(" User@example.com ", "12345678"),
                INSTALLATION_ID,
                CLIENT_IP
        );

        assertThat(response).isSameAs(expected);
        verify(rateLimitService).recordLoginSuccess("user@example.com", CLIENT_IP);
        verify(authenticationManager).authenticate(
                new UsernamePasswordAuthenticationToken("user@example.com", "12345678")
        );
    }

    @Test
    void recordsFailedAuthenticationWithoutLookingUpUser() {
        when(installationIdValidator.validate(INSTALLATION_ID)).thenReturn(INSTALLATION_ID);
        when(authenticationManager.authenticate(org.mockito.ArgumentMatchers.any()))
                .thenThrow(new BadCredentialsException("bad credentials"));

        assertThatThrownBy(() -> service.login(
                new LoginRequest("user@example.com", "wrong-pass"),
                INSTALLATION_ID,
                CLIENT_IP
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));

        verify(rateLimitService).recordLoginFailure("user@example.com", CLIENT_IP);
    }
}
