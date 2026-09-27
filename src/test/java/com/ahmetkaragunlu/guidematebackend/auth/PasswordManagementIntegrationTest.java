package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.password.PasswordManagementService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
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
import static org.mockito.Mockito.verify;

@SpringBootTest
@ActiveProfiles("test")
class PasswordManagementIntegrationTest {

    @Autowired
    private PasswordManagementService passwordManagementService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired
    private SecureTokenService secureTokenService;
    @MockitoBean
    private EmailService emailService;

    @Test
    void forgotPasswordEmailsRawTokenButPersistsOnlyItsHash() {
        User user = createActiveUser();

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

    private User createActiveUser() {
        User user = new User(
                "Auth",
                "Test",
                "password-" + UUID.randomUUID() + "@example.com",
                "not-used"
        );
        user.activate();
        return userRepository.saveAndFlush(user);
    }

    private String uniqueClientIp() {
        return "test-" + UUID.randomUUID();
    }
}
