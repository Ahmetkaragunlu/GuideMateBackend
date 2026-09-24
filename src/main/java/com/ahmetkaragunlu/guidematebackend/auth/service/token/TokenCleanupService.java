package com.ahmetkaragunlu.guidematebackend.auth.service.token;

import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final Clock clock;

    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = clock.instant();
        confirmationTokenRepository.deleteByExpiresAtBefore(now);
        passwordResetTokenRepository.deleteByExpiresAtBefore(now);
        refreshTokenRepository.deleteByExpiresAtBefore(now);
    }
}
