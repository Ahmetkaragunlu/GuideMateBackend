package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordCredentialServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private PasswordEncoder passwordEncoder;
    @Mock private PasswordPolicy passwordPolicy;
    @Mock private RefreshSessionService refreshSessionService;
    @Mock private NotificationPublisher notificationPublisher;

    private PasswordCredentialService service;

    @BeforeEach
    void setUp() {
        service = new PasswordCredentialService(
                passwordEncoder,
                passwordPolicy,
                refreshSessionService,
                notificationPublisher
        );
    }

    @Test
    void resetConsumesTokenAndInvalidatesExistingAuthentication() {
        User user = org.mockito.Mockito.mock(User.class);
        PasswordResetToken token = org.mockito.Mockito.mock(PasswordResetToken.class);
        when(passwordEncoder.encode("87654321")).thenReturn("new-hash");

        service.reset(user, token, NOW, "87654321");

        verify(user).changePasswordHash("new-hash");
        verify(user).incrementTokenVersion();
        verify(token).markUsed(NOW);
        verify(refreshSessionService).revokeAll(user);
        verify(notificationPublisher).publish(any());
    }

    @Test
    void rejectsIncorrectCurrentPasswordBeforePolicyValidation() {
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getPassword()).thenReturn("old-hash");
        when(passwordEncoder.matches("00000000", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> service.change(user, "00000000", "87654321"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CURRENT_PASSWORD_INCORRECT));

        verify(passwordPolicy, never()).validate(any());
        verify(refreshSessionService, never()).revokeAll(any());
    }

    @Test
    void changesPasswordAndInvalidatesExistingAuthentication() {
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getPassword()).thenReturn("old-hash");
        when(passwordEncoder.matches("12345678", "old-hash")).thenReturn(true);
        when(passwordEncoder.matches("87654321", "old-hash")).thenReturn(false);
        when(passwordEncoder.encode("87654321")).thenReturn("new-hash");

        service.change(user, "12345678", "87654321");

        verify(passwordPolicy).validate("87654321");
        verify(user).changePasswordHash("new-hash");
        verify(user).incrementTokenVersion();
        verify(refreshSessionService).revokeAll(user);
        verify(notificationPublisher).publish(any());
    }
}
