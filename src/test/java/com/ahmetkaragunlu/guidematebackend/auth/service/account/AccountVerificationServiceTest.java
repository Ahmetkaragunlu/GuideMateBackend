package com.ahmetkaragunlu.guidematebackend.auth.service.account;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.ConfirmationTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccountVerificationServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    @Mock private UserRepository userRepository;
    @Mock private EmailNormalizer emailNormalizer;
    @Mock private AuthRateLimitService rateLimitService;
    @Mock private ConfirmationTokenService confirmationTokenService;
    @Mock private MessageSource messageSource;
    @Mock private EmailService emailService;

    private AccountVerificationService service;

    @BeforeEach
    void setUp() {
        service = new AccountVerificationService(
                userRepository,
                emailNormalizer,
                rateLimitService,
                confirmationTokenService,
                messageSource,
                emailService
        );
    }

    @Test
    void confirmsUsableTokenForPendingAccount() {
        User user = new User("Ada", "Lovelace", "ada@example.com", "hash");
        ConfirmationToken token = org.mockito.Mockito.mock(ConfirmationToken.class);
        when(token.getUser()).thenReturn(user);
        when(confirmationTokenService.requireUsableForUpdate("raw-token"))
                .thenReturn(new ConfirmationTokenService.UsableConfirmationToken(token, NOW));
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));

        service.confirmAccount("raw-token");

        verify(token).confirm(NOW);
        assertThat(user.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    @Test
    void disabledAccountCannotConsumeConfirmationToken() {
        User user = new User("Ada", "Lovelace", "ada@example.com", "hash");
        user.disable();
        ConfirmationToken token = org.mockito.Mockito.mock(ConfirmationToken.class);
        when(token.getUser()).thenReturn(user);
        when(confirmationTokenService.requireUsableForUpdate("raw-token"))
                .thenReturn(new ConfirmationTokenService.UsableConfirmationToken(token, NOW));
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.confirmAccount("raw-token"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_DISABLED));

        verify(token, never()).confirm(NOW);
    }

    @Test
    void resendReplacesTokenOnlyForPendingAccount() {
        User user = new User("Ada", "Lovelace", "ada@example.com", "hash");
        when(emailNormalizer.normalize(" ADA@example.com ")).thenReturn("ada@example.com");
        when(userRepository.findByEmail("ada@example.com")).thenReturn(Optional.of(user));
        when(confirmationTokenService.replaceActive(user)).thenReturn("new-token");
        when(messageSource.getMessage(
                org.mockito.ArgumentMatchers.eq("auth.verification.resend"),
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.any()
        )).thenReturn("sent");

        String result = service.resendVerification(
                new ResendVerificationRequest(" ADA@example.com "),
                "203.0.113.10"
        );

        assertThat(result).isEqualTo("sent");
        verify(emailService).sendConfirmationEmail("ada@example.com", "new-token");
    }
}
