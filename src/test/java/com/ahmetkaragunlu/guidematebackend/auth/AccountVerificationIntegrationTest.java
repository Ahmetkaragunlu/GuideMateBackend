package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Clock;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;

@SpringBootTest
@ActiveProfiles("test")
class AccountVerificationIntegrationTest {

    @Autowired
    private AccountVerificationService accountVerificationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private Clock clock;
    @Autowired
    private SecureTokenService secureTokenService;
    @MockitoBean
    private EmailService emailService;

    @Test
    void confirmationTokenCannotReactivateDisabledAccount() {
        User user = createUser(AccountStatus.DISABLED);
        String rawToken = "disabled-" + UUID.randomUUID();
        ConfirmationToken token = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(user, secureTokenService.hash(rawToken), clock.instant())
        );

        assertThatThrownBy(() -> accountVerificationService.confirmAccount(rawToken))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_DISABLED));

        User persistedUser = userRepository.findById(user.getId()).orElseThrow();
        ConfirmationToken persistedToken = confirmationTokenRepository.findById(token.getId()).orElseThrow();
        assertThat(persistedUser.getAccountStatus()).isEqualTo(AccountStatus.DISABLED);
        assertThat(persistedToken.isUsed()).isFalse();
    }

    @Test
    void confirmationTokenActivatesPendingAccountOnce() {
        User user = createUser(AccountStatus.PENDING_VERIFICATION);
        String rawToken = "pending-" + UUID.randomUUID();
        ConfirmationToken token = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(user, secureTokenService.hash(rawToken), clock.instant())
        );

        accountVerificationService.confirmAccount(rawToken);

        User persistedUser = userRepository.findById(user.getId()).orElseThrow();
        ConfirmationToken persistedToken = confirmationTokenRepository.findById(token.getId()).orElseThrow();
        assertThat(persistedUser.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(persistedToken.isUsed()).isTrue();
    }

    @Test
    void resendKeepsExistingTokenActiveWhenEmailDeliveryFails() {
        User pendingUser = createUser(AccountStatus.PENDING_VERIFICATION);
        ConfirmationToken existingToken = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(
                        pendingUser,
                        secureTokenService.hash("resend-failure-" + UUID.randomUUID()),
                        clock.instant()
                )
        );
        long tokenCountBefore = confirmationTokenRepository.count();
        doThrow(new EmailDeliveryException(new IllegalStateException("SMTP unavailable")))
                .when(emailService)
                .sendConfirmationEmail(anyString(), anyString());

        assertThatThrownBy(() -> accountVerificationService.resendVerification(
                new ResendVerificationRequest(pendingUser.getEmail()),
                "resend-failure-" + UUID.randomUUID()
        )).isInstanceOf(EmailDeliveryException.class);

        ConfirmationToken persistedToken = confirmationTokenRepository.findById(existingToken.getId()).orElseThrow();
        assertThat(persistedToken.isUsed()).isFalse();
        assertThat(confirmationTokenRepository.count()).isEqualTo(tokenCountBefore);
    }

    @Test
    void resendInvalidatesExistingTokenAfterSuccessfulDelivery() {
        User pendingUser = createUser(AccountStatus.PENDING_VERIFICATION);
        ConfirmationToken existingToken = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(
                        pendingUser,
                        secureTokenService.hash("resend-success-" + UUID.randomUUID()),
                        clock.instant()
                )
        );
        long tokenCountBefore = confirmationTokenRepository.count();

        accountVerificationService.resendVerification(
                new ResendVerificationRequest(pendingUser.getEmail()),
                "resend-success-" + UUID.randomUUID()
        );

        ConfirmationToken persistedToken = confirmationTokenRepository.findById(existingToken.getId()).orElseThrow();
        assertThat(persistedToken.isUsed()).isTrue();
        assertThat(confirmationTokenRepository.count()).isEqualTo(tokenCountBefore + 1);
    }

    private User createUser(AccountStatus status) {
        User user = new User(
                "Auth",
                "Test",
                "verification-" + UUID.randomUUID() + "@example.com",
                "not-used"
        );
        if (status == AccountStatus.DISABLED) {
            user.disable();
        }
        return userRepository.saveAndFlush(user);
    }
}
