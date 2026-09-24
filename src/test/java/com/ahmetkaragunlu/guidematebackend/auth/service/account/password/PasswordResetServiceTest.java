package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.PasswordResetTokenService;
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
import org.springframework.context.MessageSource;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private UserRepository userRepository;
    @Mock private EmailNormalizer emailNormalizer;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private PasswordResetTokenService passwordResetTokenService;
    @Mock private PasswordCredentialService passwordCredentialService;
    @Mock private MessageSource messageSource;
    @Mock private EmailService emailService;

    private PasswordResetService service;

    @BeforeEach
    void setUp() {
        service = new PasswordResetService(
                userRepository,
                emailNormalizer,
                rateLimitService,
                accountStatusPolicy,
                passwordResetTokenService,
                passwordCredentialService,
                messageSource,
                emailService
        );
    }

    @Test
    void resetsPasswordUsingLockedTokenAndUser() {
        User user = org.mockito.Mockito.mock(User.class);
        PasswordResetToken token = org.mockito.Mockito.mock(PasswordResetToken.class);
        when(user.getId()).thenReturn(42L);
        when(token.getUser()).thenReturn(user);
        when(passwordResetTokenService.requireUsableForUpdate("raw-token"))
                .thenReturn(new PasswordResetTokenService.UsablePasswordResetToken(token, NOW));
        when(userRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(user));
        when(messageSource.getMessage("auth.password.reset", null, Locale.getDefault()))
                .thenReturn("reset");

        String result = service.resetPassword(new ResetPasswordRequest(
                "raw-token",
                "87654321",
                "87654321"
        ));

        assertThat(result).isEqualTo("reset");
        verify(passwordCredentialService).validateNewPassword("87654321");
        verify(passwordCredentialService).reset(user, token, NOW, "87654321");
    }

    @Test
    void rejectsMismatchingPasswordsBeforeTokenLookup() {
        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest(
                "raw-token",
                "87654321",
                "12345678"
        ))).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PASSWORDS_DO_NOT_MATCH));

        verify(passwordCredentialService).validateNewPassword("87654321");
        verify(passwordResetTokenService, never()).requireUsableForUpdate(anyString());
    }

    @Test
    void forgotPasswordDoesNotRevealUnknownAccount() {
        when(emailNormalizer.normalize("unknown@example.com")).thenReturn("unknown@example.com");
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());
        when(messageSource.getMessage("auth.forgotPassword.sent", null, Locale.getDefault()))
                .thenReturn("sent");

        String result = service.forgotPassword(
                new ForgotPasswordRequest("unknown@example.com"),
                "203.0.113.10"
        );

        assertThat(result).isEqualTo("sent");
        verify(passwordResetTokenService, never()).replaceActive(org.mockito.ArgumentMatchers.any());
        verify(emailService, never()).sendPasswordResetEmail(anyString(), anyString());
    }
}
