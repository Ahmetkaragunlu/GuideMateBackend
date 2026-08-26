package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.service.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;

@SpringBootTest
@ActiveProfiles("test")
class AuthLifecycleIntegrationTest {

    @Autowired
    private AccountVerificationService accountVerificationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private Clock clock;
    @MockitoBean
    private EmailService emailService;

    @Test
    void confirmationTokenCannotReactivateDisabledAccount() {
        User user = createUser(AccountStatus.DISABLED);
        ConfirmationToken token = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(user, "disabled-" + UUID.randomUUID(), localNow())
        );

        assertThatThrownBy(() -> accountVerificationService.confirmAccount(token.getToken()))
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
                new ConfirmationToken(user, "pending-" + UUID.randomUUID(), localNow())
        );

        accountVerificationService.confirmAccount(token.getToken());

        User persistedUser = userRepository.findById(user.getId()).orElseThrow();
        ConfirmationToken persistedToken = confirmationTokenRepository.findById(token.getId()).orElseThrow();
        assertThat(persistedUser.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(persistedToken.isUsed()).isTrue();
    }

    @Test
    void registrationPersistsPendingAccountAndTokenWhenEmailDeliveryFails() {
        String email = "register-" + UUID.randomUUID() + "@example.com";
        long tokenCountBefore = confirmationTokenRepository.count();
        doThrow(new EmailDeliveryException(new IllegalStateException("SMTP unavailable")))
                .when(emailService)
                .sendConfirmationEmail(anyString(), anyString());

        assertThatThrownBy(() -> accountVerificationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                email,
                "12345678"
        ))).isInstanceOf(EmailDeliveryException.class);

        User persistedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(persistedUser.getAccountStatus()).isEqualTo(AccountStatus.PENDING_VERIFICATION);
        assertThat(confirmationTokenRepository.count()).isEqualTo(tokenCountBefore + 1);
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

    private LocalDateTime localNow() {
        return LocalDateTime.ofInstant(clock.instant(), ZoneId.systemDefault());
    }
}
