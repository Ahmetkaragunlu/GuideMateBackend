package com.ahmetkaragunlu.guidematebackend.auth.service.token;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordResetTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private PasswordResetTokenRepository repository;
    @Mock private SecureTokenService secureTokenService;

    private PasswordResetTokenService service;

    @BeforeEach
    void setUp() {
        service = new PasswordResetTokenService(
                repository,
                secureTokenService,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void returnsLockedUsableTokenWithValidationTimestamp() {
        PasswordResetToken token = org.mockito.Mockito.mock(PasswordResetToken.class);
        when(secureTokenService.hash("raw-token")).thenReturn("token-hash");
        when(repository.findByTokenHashForUpdate("token-hash")).thenReturn(Optional.of(token));

        var result = service.requireUsableForUpdate("raw-token");

        assertThat(result.token()).isSameAs(token);
        assertThat(result.validatedAt()).isEqualTo(NOW);
    }

    @Test
    void rejectsExpiredToken() {
        PasswordResetToken token = org.mockito.Mockito.mock(PasswordResetToken.class);
        when(secureTokenService.hash("raw-token")).thenReturn("token-hash");
        when(repository.findByTokenHash("token-hash")).thenReturn(Optional.of(token));
        when(token.isExpired(NOW)).thenReturn(true);

        assertThatThrownBy(() -> service.requireUsable("raw-token"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.TOKEN_EXPIRED));
    }
}
