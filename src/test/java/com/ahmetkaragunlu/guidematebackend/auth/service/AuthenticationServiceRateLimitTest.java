package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.notification.service.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceRateLimitTest {

    private static final String INSTALLATION_ID = "11111111-1111-4111-8111-111111111111";
    private static final String CLIENT_IP = "203.0.113.10";

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private EmailNormalizer emailNormalizer;
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
                emailNormalizer,
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
}
