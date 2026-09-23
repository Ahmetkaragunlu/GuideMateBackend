package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordManagementServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private UserRepository userRepository;
    @Mock private PasswordResetTokenRepository tokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private SecureTokenService secureTokenService;
    @Mock private PasswordPolicy passwordPolicy;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private MessageSource messageSource;
    @Mock private EmailService emailService;
    @Mock private RefreshSessionService refreshSessionService;
    @Mock private NotificationPublisher notificationPublisher;

    private PasswordManagementService service;

    @BeforeEach
    void setUp() {
        service = new PasswordManagementService(
                userRepository,
                tokenRepository,
                passwordEncoder,
                secureTokenService,
                new EmailNormalizer(),
                passwordPolicy,
                rateLimitService,
                accountStatusPolicy,
                messageSource,
                emailService,
                refreshSessionService,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void resetsPasswordConsumesTokenAndRevokesAllSessions() {
        User user = mock(User.class);
        PasswordResetToken token = mock(PasswordResetToken.class);
        when(user.getId()).thenReturn(42L);
        when(token.getUser()).thenReturn(user);
        when(secureTokenService.hash("raw-token")).thenReturn("token-hash");
        when(tokenRepository.findByTokenHashForUpdate("token-hash")).thenReturn(Optional.of(token));
        when(userRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("87654321")).thenReturn("new-hash");
        message("auth.password.reset");

        String result = service.resetPassword(new ResetPasswordRequest(
                "raw-token",
                "87654321",
                "87654321"
        ));

        assertThat(result).isEqualTo("auth.password.reset");
        verify(user).changePasswordHash("new-hash");
        verify(user).incrementTokenVersion();
        verify(token).markUsed(NOW);
        verify(refreshSessionService).revokeAll(user);
        verify(notificationPublisher).publish(any());
    }

    @Test
    void rejectsExpiredResetTokenWithoutChangingPassword() {
        PasswordResetToken token = mock(PasswordResetToken.class);
        when(secureTokenService.hash("raw-token")).thenReturn("token-hash");
        when(tokenRepository.findByTokenHashForUpdate("token-hash")).thenReturn(Optional.of(token));
        when(token.isExpired(NOW)).thenReturn(true);

        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest(
                "raw-token",
                "87654321",
                "87654321"
        ))).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.TOKEN_EXPIRED));
        verify(refreshSessionService, never()).revokeAll(any());
    }

    @Test
    void rejectsMismatchingResetPasswordsBeforeConsumingToken() {
        assertThatThrownBy(() -> service.resetPassword(new ResetPasswordRequest(
                "raw-token",
                "87654321",
                "12345678"
        ))).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PASSWORDS_DO_NOT_MATCH));
        verify(tokenRepository, never()).findByTokenHashForUpdate(anyString());
    }

    @Test
    void changesPasswordAndInvalidatesExistingAuthentication() {
        User user = mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(user.getPassword()).thenReturn("old-hash");
        when(userRepository.findByEmailForUpdate("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("12345678", "old-hash")).thenReturn(true);
        when(passwordEncoder.matches("87654321", "old-hash")).thenReturn(false);
        when(passwordEncoder.encode("87654321")).thenReturn("new-hash");
        message("auth.password.changed");

        String result = service.changePassword(
                new ChangePasswordRequest("12345678", "87654321"),
                " User@Example.com "
        );

        assertThat(result).isEqualTo("auth.password.changed");
        verify(user).changePasswordHash("new-hash");
        verify(user).incrementTokenVersion();
        verify(refreshSessionService).revokeAll(user);
        verify(notificationPublisher).publish(any());
    }

    @Test
    void rejectsIncorrectCurrentPasswordWithoutRevokingSessions() {
        User user = mock(User.class);
        when(user.getPassword()).thenReturn("old-hash");
        when(userRepository.findByEmailForUpdate("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("00000000", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> service.changePassword(
                new ChangePasswordRequest("00000000", "87654321"),
                "user@example.com"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CURRENT_PASSWORD_INCORRECT));
        verify(refreshSessionService, never()).revokeAll(any());
    }

    private void message(String key) {
        when(messageSource.getMessage(key, null, Locale.getDefault())).thenReturn(key);
    }
}
