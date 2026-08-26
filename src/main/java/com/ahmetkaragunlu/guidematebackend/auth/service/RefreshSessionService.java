package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.RefreshToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.RefreshTokenRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshSessionService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final SecureTokenService tokenService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final Clock clock;
    private final long refreshExpirationMillis;

    public RefreshSessionService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            SecureTokenService tokenService,
            AccountStatusPolicy accountStatusPolicy,
            Clock clock,
            @Value("${jwt.refresh-expiration}") long refreshExpirationMillis
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.accountStatusPolicy = accountStatusPolicy;
        this.clock = clock;
        this.refreshExpirationMillis = refreshExpirationMillis;
    }

    @Transactional
    public String createSession(User user, String installationId) {
        User lockedUser = userRepository.findByIdForUpdate(user.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        Instant now = clock.instant();
        refreshTokenRepository.revokeActiveForInstallation(lockedUser, installationId, now);

        String rawToken = tokenService.generate();
        RefreshToken session = new RefreshToken(
                lockedUser,
                tokenService.hash(rawToken),
                UUID.randomUUID().toString(),
                installationId,
                now.plusMillis(refreshExpirationMillis)
        );
        refreshTokenRepository.save(session);
        return rawToken;
    }

    @Transactional
    public RefreshRotationResult rotate(String rawToken, String installationId) {
        String tokenHash = tokenService.hash(rawToken);
        RefreshToken current = refreshTokenRepository.findByTokenHashForUpdate(tokenHash).orElse(null);
        if (current == null) {
            return RefreshRotationResult.failure(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        Instant now = clock.instant();
        if (!current.getInstallationId().equals(installationId)) {
            return RefreshRotationResult.failure(ErrorCode.INVALID_REFRESH_TOKEN);
        }
        if (current.isRevoked()) {
            refreshTokenRepository.revokeActiveFamily(current.getFamilyId(), now);
            return RefreshRotationResult.failure(ErrorCode.REFRESH_TOKEN_REPLAY);
        }
        if (current.isExpired(now)) {
            current.revoke(now);
            return RefreshRotationResult.failure(ErrorCode.REFRESH_TOKEN_EXPIRED);
        }
        Optional<ErrorCode> accountError = accountStatusPolicy.accessError(current.getUser());
        if (accountError.isPresent()) {
            refreshTokenRepository.revokeActiveFamily(current.getFamilyId(), now);
            return RefreshRotationResult.failure(accountError.get());
        }

        current.revoke(now);
        String newRawToken = tokenService.generate();
        RefreshToken replacement = new RefreshToken(
                current.getUser(),
                tokenService.hash(newRawToken),
                current.getFamilyId(),
                installationId,
                now.plusMillis(refreshExpirationMillis)
        );
        refreshTokenRepository.save(replacement);
        initializeRole(current.getUser());
        return RefreshRotationResult.success(current.getUser(), newRawToken);
    }

    @Transactional
    public void revoke(String rawToken, String principalEmail, String installationId) {
        RefreshToken session = refreshTokenRepository
                .findByTokenHashForUpdate(tokenService.hash(rawToken))
                .orElse(null);
        if (session == null || session.isRevoked()) {
            return;
        }
        if (!session.getUser().getEmail().equals(principalEmail)
                || !session.getInstallationId().equals(installationId)) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }
        session.revoke(clock.instant());
    }

    @Transactional
    public void revokeAll(User user) {
        refreshTokenRepository.revokeAllActiveByUser(user, clock.instant());
    }

    private void initializeRole(User user) {
        if (user.getRole() != null) {
            user.getRole().getName();
        }
    }

    public record RefreshRotationResult(
            User user,
            String rawRefreshToken,
            ErrorCode errorCode
    ) {
        public static RefreshRotationResult success(User user, String rawRefreshToken) {
            return new RefreshRotationResult(user, rawRefreshToken, null);
        }

        public static RefreshRotationResult failure(ErrorCode errorCode) {
            return new RefreshRotationResult(null, null, errorCode);
        }

        public boolean isSuccessful() {
            return errorCode == null;
        }
    }
}
