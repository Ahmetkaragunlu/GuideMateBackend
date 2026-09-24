package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.RegistrationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.password.PasswordManagementService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login.AuthenticationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Clock;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@SpringBootTest
@ActiveProfiles("test")
class AuthLifecycleIntegrationTest {

    @Autowired
    private AccountVerificationService accountVerificationService;
    @Autowired
    private RegistrationService registrationService;
    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private PasswordManagementService passwordManagementService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired
    private Clock clock;
    @Autowired
    private PasswordEncoder passwordEncoder;
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
    void registrationPersistsPendingAccountAndTokenWhenEmailDeliveryFails() {
        String email = "register-" + UUID.randomUUID() + "@example.com";
        long tokenCountBefore = confirmationTokenRepository.count();
        doThrow(new EmailDeliveryException(new IllegalStateException("SMTP unavailable")))
                .when(emailService)
                .sendConfirmationEmail(anyString(), anyString());

        assertThatThrownBy(() -> registrationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                email,
                "12345678"
        ), uniqueClientIp())).isInstanceOf(EmailDeliveryException.class);

        User persistedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(persistedUser.getAccountStatus()).isEqualTo(AccountStatus.PENDING_VERIFICATION);
        assertThat(confirmationTokenRepository.count()).isEqualTo(tokenCountBefore + 1);
    }

    @Test
    void registrationEmailsRawTokenButPersistsOnlyItsHash() {
        String email = "hash-register-" + UUID.randomUUID() + "@example.com";

        registrationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                email,
                "12345678"
        ), uniqueClientIp());

        ArgumentCaptor<String> rawTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendConfirmationEmail(
                org.mockito.ArgumentMatchers.eq(email),
                rawTokenCaptor.capture()
        );
        String rawToken = rawTokenCaptor.getValue();
        Long userId = userRepository.findByEmail(email).orElseThrow().getId();
        ConfirmationToken persistedToken = confirmationTokenRepository.findAll().stream()
                .filter(token -> token.getUser().getId().equals(userId))
                .findFirst()
                .orElseThrow();

        assertThat(persistedToken.getTokenHash()).isEqualTo(secureTokenService.hash(rawToken));
        assertThat(persistedToken.getTokenHash()).isNotEqualTo(rawToken);
    }

    @Test
    void forgotPasswordEmailsRawTokenButPersistsOnlyItsHash() {
        User user = createUser(AccountStatus.ACTIVE);

        passwordManagementService.forgotPassword(
                new ForgotPasswordRequest(user.getEmail()),
                uniqueClientIp()
        );

        ArgumentCaptor<String> rawTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendPasswordResetEmail(
                org.mockito.ArgumentMatchers.eq(user.getEmail()),
                rawTokenCaptor.capture()
        );
        String rawToken = rawTokenCaptor.getValue();
        var persistedToken = passwordResetTokenRepository.findAll().stream()
                .filter(token -> token.getUser().getId().equals(user.getId()))
                .findFirst()
                .orElseThrow();

        assertThat(persistedToken.getTokenHash()).isEqualTo(secureTokenService.hash(rawToken));
        assertThat(persistedToken.getTokenHash()).isNotEqualTo(rawToken);
    }

    @Test
    void registrationReportsPendingVerificationForExistingPendingAccount() {
        User pendingUser = createUser(AccountStatus.PENDING_VERIFICATION);

        assertThatThrownBy(() -> registrationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                pendingUser.getEmail(),
                "12345678"
        ), uniqueClientIp())).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_PENDING_VERIFICATION));
    }

    @Test
    void registrationReportsExistingEmailForActiveAccount() {
        User activeUser = createUser(AccountStatus.ACTIVE);

        assertThatThrownBy(() -> registrationService.register(new RegisterRequest(
                "Auth",
                "Tester",
                activeUser.getEmail(),
                "12345678"
        ), uniqueClientIp())).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS));
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
        User user = new User(
                "Auth",
                "Test",
                "auth-" + UUID.randomUUID() + "@example.com",
                "not-used"
        );
        if (status == AccountStatus.ACTIVE) {
            user.activate();
        } else if (status == AccountStatus.DISABLED) {
            user.disable();
        }
        return userRepository.saveAndFlush(user);
    }

    private User createLoginUser(AccountStatus status, String rawPassword) {
        User user = createUser(status);
        user.changePasswordHash(passwordEncoder.encode(rawPassword));
        return userRepository.saveAndFlush(user);
    }

    private String uniqueClientIp() {
        return "test-" + UUID.randomUUID();
    }
}
