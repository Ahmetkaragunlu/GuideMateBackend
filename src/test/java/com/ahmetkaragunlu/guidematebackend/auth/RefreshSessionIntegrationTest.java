package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.RefreshToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.RefreshTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.service.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class RefreshSessionIntegrationTest {

    private static final String INSTALLATION_ID = "550e8400-e29b-41d4-a716-446655440000";

    @Autowired
    private RefreshSessionService refreshSessionService;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private SecureTokenService secureTokenService;
    @Autowired
    private Clock clock;

    @Test
    void rotatesRefreshTokenWithinSameFamily() {
        User user = createUser(AccountStatus.ACTIVE);
        String originalRawToken = refreshSessionService.createSession(user, INSTALLATION_ID);
        RefreshToken original = findByRawToken(originalRawToken);

        RefreshSessionService.RefreshRotationResult result = refreshSessionService.rotate(
                originalRawToken,
                INSTALLATION_ID
        );

        assertThat(result.isSuccessful()).isTrue();
        assertThat(result.user().getId()).isEqualTo(user.getId());
        assertThat(result.rawRefreshToken()).isNotBlank().isNotEqualTo(originalRawToken);
        assertThat(findByRawToken(originalRawToken).isRevoked()).isTrue();
        RefreshToken replacement = findByRawToken(result.rawRefreshToken());
        assertThat(replacement.getFamilyId()).isEqualTo(original.getFamilyId());
        assertThat(replacement.isRevoked()).isFalse();
    }

    @Test
    void replayRevokesReplacementTokenFamily() {
        User user = createUser(AccountStatus.ACTIVE);
        String originalRawToken = refreshSessionService.createSession(user, INSTALLATION_ID);
        RefreshSessionService.RefreshRotationResult rotation = refreshSessionService.rotate(
                originalRawToken,
                INSTALLATION_ID
        );

        RefreshSessionService.RefreshRotationResult replay = refreshSessionService.rotate(
                originalRawToken,
                INSTALLATION_ID
        );
        RefreshSessionService.RefreshRotationResult replacementAttempt = refreshSessionService.rotate(
                rotation.rawRefreshToken(),
                INSTALLATION_ID
        );

        assertThat(replay.errorCode()).isEqualTo(ErrorCode.REFRESH_TOKEN_REPLAY);
        assertThat(replacementAttempt.errorCode()).isEqualTo(ErrorCode.REFRESH_TOKEN_REPLAY);
        assertThat(findByRawToken(rotation.rawRefreshToken()).isRevoked()).isTrue();
    }

    @Test
    void installationMismatchDoesNotConsumeValidToken() {
        User user = createUser(AccountStatus.ACTIVE);
        String rawToken = refreshSessionService.createSession(user, INSTALLATION_ID);

        RefreshSessionService.RefreshRotationResult mismatch = refreshSessionService.rotate(
                rawToken,
                "11111111-1111-4111-8111-111111111111"
        );

        assertThat(mismatch.errorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
        assertThat(findByRawToken(rawToken).isRevoked()).isFalse();
        assertThat(refreshSessionService.rotate(rawToken, INSTALLATION_ID).isSuccessful()).isTrue();
    }

    @Test
    void rejectsExpiredRefreshTokenAndRevokesIt() {
        User user = createUser(AccountStatus.ACTIVE);
        String rawToken = "expired-" + UUID.randomUUID();
        RefreshToken expired = new RefreshToken(
                user,
                secureTokenService.hash(rawToken),
                UUID.randomUUID().toString(),
                INSTALLATION_ID,
                clock.instant().minus(Duration.ofSeconds(1))
        );
        refreshTokenRepository.saveAndFlush(expired);

        RefreshSessionService.RefreshRotationResult result = refreshSessionService.rotate(rawToken, INSTALLATION_ID);

        assertThat(result.errorCode()).isEqualTo(ErrorCode.REFRESH_TOKEN_EXPIRED);
        assertThat(findByRawToken(rawToken).isRevoked()).isTrue();
    }

    @Test
    void accountStatusFailureRevokesTokenFamily() {
        User user = createUser(AccountStatus.ACTIVE);
        String rawToken = refreshSessionService.createSession(user, INSTALLATION_ID);
        user.setAccountStatus(AccountStatus.DISABLED);
        userRepository.saveAndFlush(user);

        RefreshSessionService.RefreshRotationResult result = refreshSessionService.rotate(rawToken, INSTALLATION_ID);

        assertThat(result.errorCode()).isEqualTo(ErrorCode.ACCOUNT_DISABLED);
        assertThat(findByRawToken(rawToken).isRevoked()).isTrue();
    }

    @Test
    void logoutRejectsDifferentInstallationWithoutRevokingSession() {
        User user = createUser(AccountStatus.ACTIVE);
        String rawToken = refreshSessionService.createSession(user, INSTALLATION_ID);

        assertThatThrownBy(() -> refreshSessionService.revoke(
                rawToken,
                user.getEmail(),
                "11111111-1111-4111-8111-111111111111"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN));

        assertThat(findByRawToken(rawToken).isRevoked()).isFalse();
        assertThatCode(() -> refreshSessionService.revoke(rawToken, user.getEmail(), INSTALLATION_ID))
                .doesNotThrowAnyException();
        assertThat(findByRawToken(rawToken).isRevoked()).isTrue();
    }

    private RefreshToken findByRawToken(String rawToken) {
        String tokenHash = secureTokenService.hash(rawToken);
        return refreshTokenRepository.findAll().stream()
                .filter(token -> token.getTokenHash().equals(tokenHash))
                .findFirst()
                .orElseThrow();
    }

    private User createUser(AccountStatus status) {
        User user = new User();
        user.setFirstName("Refresh");
        user.setLastName("Tester");
        user.setEmail("refresh-" + UUID.randomUUID() + "@example.com");
        user.setPassword("not-used");
        user.setAccountStatus(status);
        return userRepository.saveAndFlush(user);
    }
}
