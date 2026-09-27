package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.RegistrationService;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@SpringBootTest
@ActiveProfiles("test")
class RegistrationIntegrationTest {

    @Autowired
    private RegistrationService registrationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private SecureTokenService secureTokenService;
    @MockitoBean
    private EmailService emailService;

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

    private User createUser(AccountStatus status) {
        User user = new User(
                "Auth",
                "Test",
                "registration-" + UUID.randomUUID() + "@example.com",
                "not-used"
        );
        if (status == AccountStatus.ACTIVE) {
            user.activate();
        }
        return userRepository.saveAndFlush(user);
    }

    private String uniqueClientIp() {
        return "test-" + UUID.randomUUID();
    }
}
