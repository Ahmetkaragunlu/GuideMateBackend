package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.exception.RateLimitException;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccountVerificationServiceTest {

    private static final String EMAIL = "tourist@example.com";
    private static final String CLIENT_IP = "203.0.113.10";

    @Mock private UserRepository userRepository;
    @Mock private ConfirmationTokenRepository confirmationTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private SecureTokenService secureTokenService;
    @Mock private EmailNormalizer emailNormalizer;
    @Mock private PasswordPolicy passwordPolicy;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private RegistrationConflictVerifier registrationConflictVerifier;
    @Mock private MessageSource messageSource;
    @Mock private EmailService emailService;
    @Mock private Clock clock;

    private AccountVerificationService service;

    @BeforeEach
    void setUp() {
        service = new AccountVerificationService(
                userRepository,
                confirmationTokenRepository,
                passwordEncoder,
                secureTokenService,
                emailNormalizer,
                passwordPolicy,
                rateLimitService,
                registrationConflictVerifier,
                messageSource,
                emailService,
                clock
        );
    }

    @Test
    void rateLimitStopsRegistrationBeforePasswordAndPersistenceWork() {
        when(emailNormalizer.normalize(EMAIL)).thenReturn(EMAIL);
        org.mockito.Mockito.doThrow(new RateLimitException(60))
                .when(rateLimitService)
                .acquireRegistrationPermit(EMAIL, CLIENT_IP);

        assertThatThrownBy(() -> service.register(request(), CLIENT_IP))
                .isInstanceOf(RateLimitException.class);

        verifyNoInteractions(passwordPolicy, userRepository, passwordEncoder, emailService);
    }

    @Test
    void mapsIntegrityFailureToDuplicateOnlyWhenEmailNowExists() {
        DataIntegrityViolationException conflict = new DataIntegrityViolationException("constraint");
        preparePersistenceConflict(conflict);
        when(registrationConflictVerifier.emailExists(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> service.register(request(), CLIENT_IP))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS));

        verify(emailService, never()).sendConfirmationEmail(any(), any());
    }

    @Test
    void preservesUnrelatedIntegrityFailureForGlobalConflictHandling() {
        DataIntegrityViolationException conflict = new DataIntegrityViolationException("constraint");
        preparePersistenceConflict(conflict);
        when(registrationConflictVerifier.emailExists(EMAIL)).thenReturn(false);

        assertThatThrownBy(() -> service.register(request(), CLIENT_IP)).isSameAs(conflict);
    }

    private void preparePersistenceConflict(DataIntegrityViolationException conflict) {
        when(emailNormalizer.normalize(EMAIL)).thenReturn(EMAIL);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("12345678")).thenReturn("encoded-password");
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(conflict);
    }

    private RegisterRequest request() {
        return new RegisterRequest("Ada", "Lovelace", EMAIL, "12345678");
    }
}
