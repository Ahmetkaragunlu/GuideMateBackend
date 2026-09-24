package com.ahmetkaragunlu.guidematebackend.auth.service.token;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
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
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final SecureTokenService secureTokenService;
    private final Clock clock;

    public String issue(User user) {
        return create(user, clock.instant());
    }

    public String replaceActive(User user) {
        Instant now = clock.instant();
        confirmationTokenRepository.invalidateActiveTokens(user.getId(), now);
        return create(user, now);
    }

    public UsableConfirmationToken requireUsableForUpdate(String rawToken) {
        ConfirmationToken token = confirmationTokenRepository
                .findByTokenHashForUpdate(secureTokenService.hash(rawToken))
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        Instant now = clock.instant();
        if (token.isConfirmed() || token.isUsed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }
        if (token.isExpired(now)) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }
        return new UsableConfirmationToken(token, now);
    }

    private String create(User user, Instant now) {
        String rawToken = secureTokenService.generate();
        confirmationTokenRepository.save(
                new ConfirmationToken(user, secureTokenService.hash(rawToken), now)
        );
        return rawToken;
    }

    public record UsableConfirmationToken(ConfirmationToken token, Instant validatedAt) {
    }
}
