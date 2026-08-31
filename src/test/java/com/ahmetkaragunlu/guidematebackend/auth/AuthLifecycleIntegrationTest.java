package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.service.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.AuthenticationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private AuthenticationService authenticationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private Clock clock;
    @Autowired
    private PasswordEncoder passwordEncoder;
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

    @Test
    void registrationReportsPendingVerificationForExistingPendingAccount() {
        User pendingUser = createUser(AccountStatus.PENDING_VERIFICATION);

        assertThatThrownBy(() -> accountVerificationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                pendingUser.getEmail(),
                "12345678"
        ))).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_PENDING_VERIFICATION));
    }

    @Test
    void registrationReportsExistingEmailForActiveAccount() {
        User activeUser = createUser(AccountStatus.ACTIVE);

        assertThatThrownBy(() -> accountVerificationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                activeUser.getEmail(),
                "12345678"
        ))).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS));
    }

    @Test
    void resendKeepsExistingTokenActiveWhenEmailDeliveryFails() {
        User pendingUser = createUser(AccountStatus.PENDING_VERIFICATION);
        ConfirmationToken existingToken = confirmationTokenRepository.saveAndFlush(
                new ConfirmationToken(pendingUser, "resend-failure-" + UUID.randomUUID(), localNow())
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
                new ConfirmationToken(pendingUser, "resend-success-" + UUID.randomUUID(), localNow())
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

    @Test
    void pendingAccountWithWrongPasswordReturnsInvalidCredentials() {
        User user = createLoginUser(AccountStatus.PENDING_VERIFICATION, "12345678");

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), "87654321"),
                UUID.randomUUID().toString(),
                "127.0.0.10"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    @Test
    void pendingAccountWithCorrectPasswordReturnsPendingVerification() {
        User user = createLoginUser(AccountStatus.PENDING_VERIFICATION, "12345678");

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), "12345678"),
                UUID.randomUUID().toString(),
                "127.0.0.11"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_PENDING_VERIFICATION));
    }

    @Test
    void disabledAccountWithWrongPasswordReturnsInvalidCredentials() {
        User user = createLoginUser(AccountStatus.DISABLED, "12345678");

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), "87654321"),
                UUID.randomUUID().toString(),
                "127.0.0.12"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    @Test
    void disabledAccountWithCorrectPasswordReturnsAccountDisabled() {
        User user = createLoginUser(AccountStatus.DISABLED, "12345678");

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), "12345678"),
                UUID.randomUUID().toString(),
                "127.0.0.13"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_DISABLED));
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

    private User createLoginUser(AccountStatus status, String rawPassword) {
        User user = createUser(status);
        user.setPassword(passwordEncoder.encode(rawPassword));
        return userRepository.saveAndFlush(user);
    }

    private LocalDateTime localNow() {
        return LocalDateTime.ofInstant(clock.instant(), ZoneId.systemDefault());
    }
}
