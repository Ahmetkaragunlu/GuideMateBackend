package com.ahmetkaragunlu.guidematebackend.auth.service.token;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ConfirmationTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private ConfirmationTokenRepository repository;
    @Mock private SecureTokenService secureTokenService;

    private ConfirmationTokenService service;

    @BeforeEach
    void setUp() {
        service = new ConfirmationTokenService(
                repository,
                secureTokenService,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void replacesActiveTokenUsingOneConsistentTimestamp() {
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(secureTokenService.generate()).thenReturn("raw-token");
        when(secureTokenService.hash("raw-token")).thenReturn("token-hash");

        String result = service.replaceActive(user);

        assertThat(result).isEqualTo("raw-token");
        verify(repository).invalidateActiveTokens(42L, NOW);
        verify(repository).save(org.mockito.ArgumentMatchers.argThat(token ->
                token.getUser() == user && token.getTokenHash().equals("token-hash")
        ));
    }

    @Test
    void rejectsAlreadyUsedTokenBeforeExpiryCheck() {
        ConfirmationToken token = org.mockito.Mockito.mock(ConfirmationToken.class);
        when(secureTokenService.hash("raw-token")).thenReturn("token-hash");
        when(repository.findByTokenHashForUpdate("token-hash")).thenReturn(Optional.of(token));
        when(token.isUsed()).thenReturn(true);

        assertThatThrownBy(() -> service.requireUsableForUpdate("raw-token"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.TOKEN_ALREADY_USED));
    }
}
