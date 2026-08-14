package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.service.AuthService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class AuthLifecycleIntegrationTest {

    @Autowired
    private AuthService authService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;

    @Test
    void confirmationTokenCannotReactivateDisabledAccount() {
        User user = createUser(AccountStatus.DISABLED);
        ConfirmationToken token = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(user, "disabled-" + UUID.randomUUID())
        );

        assertThatThrownBy(() -> authService.confirmAccount(token.getToken()))
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
        ConfirmationToken token = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(user, "pending-" + UUID.randomUUID())
        );

        authService.confirmAccount(token.getToken());

        User persistedUser = userRepository.findById(user.getId()).orElseThrow();
        ConfirmationToken persistedToken = confirmationTokenRepository.findById(token.getId()).orElseThrow();
        assertThat(persistedUser.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(persistedToken.isUsed()).isTrue();
    }

    private User createUser(AccountStatus status) {
        User user = new User();
        user.setFirstName("Auth");
        user.setLastName("Test");
        user.setEmail("auth-" + UUID.randomUUID() + "@example.com");
        user.setPassword("not-used");
        user.setAccountStatus(status);
        return userRepository.saveAndFlush(user);
    }
}
