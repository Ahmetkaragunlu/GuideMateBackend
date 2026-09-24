package com.ahmetkaragunlu.guidematebackend.auth.service.token;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SecureTokenService secureTokenService;
    private final Clock clock;

    public String replaceActive(User user) {
        Instant now = clock.instant();
        passwordResetTokenRepository.invalidateActiveTokens(user.getId(), now);
        String rawToken = secureTokenService.generate();
        passwordResetTokenRepository.save(new PasswordResetToken(
                user,
                secureTokenService.hash(rawToken),
                now
        ));
        return rawToken;
    }

    public UsablePasswordResetToken requireUsableForUpdate(String rawToken) {
        PasswordResetToken token = passwordResetTokenRepository
                .findByTokenHashForUpdate(secureTokenService.hash(rawToken))
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        return validate(token);
    }

    public void requireUsable(String rawToken) {
        PasswordResetToken token = passwordResetTokenRepository
                .findByTokenHash(secureTokenService.hash(rawToken))
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        validate(token);
    }

    private UsablePasswordResetToken validate(PasswordResetToken token) {
        Instant now = clock.instant();
        if (token.isUsed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }
        if (token.isExpired(now)) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }
        return new UsablePasswordResetToken(token, now);
    }

    public record UsablePasswordResetToken(PasswordResetToken token, Instant validatedAt) {
    }
}
