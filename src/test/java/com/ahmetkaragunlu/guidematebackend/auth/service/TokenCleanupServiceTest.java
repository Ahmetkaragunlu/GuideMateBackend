package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.RefreshTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.mockito.Mockito.inOrder;

@ExtendWith(MockitoExtension.class)
class TokenCleanupServiceTest {

    @Mock private RefreshTokenRepository refreshRepository;
    @Mock private ConfirmationTokenRepository confirmationRepository;
    @Mock private PasswordResetTokenRepository resetRepository;

    @Test
    void deletesEveryExpiredTokenFamilyAtSameCutoff() {
        Instant now = Instant.parse("2026-09-24T03:00:00Z");
        TokenCleanupService service = new TokenCleanupService(
                refreshRepository,
                confirmationRepository,
                resetRepository,
                Clock.fixed(now, ZoneOffset.UTC)
        );

        service.cleanupExpiredTokens();

        InOrder order = inOrder(confirmationRepository, resetRepository, refreshRepository);
        order.verify(confirmationRepository).deleteByExpiresAtBefore(now);
        order.verify(resetRepository).deleteByExpiresAtBefore(now);
        order.verify(refreshRepository).deleteByExpiresAtBefore(now);
    }
}
