package com.ahmetkaragunlu.guidematebackend.auth;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login.AuthenticationService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class AuthenticationAccountStatusIntegrationTest {

    private static final String PASSWORD = "12345678";

    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void pendingAccountWithWrongPasswordReturnsInvalidCredentials() {
        User user = createLoginUser(AccountStatus.PENDING_VERIFICATION);

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), "87654321"),
                UUID.randomUUID().toString(),
                "127.0.0.10"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    @Test
    void pendingAccountWithCorrectPasswordReturnsPendingVerification() {
        User user = createLoginUser(AccountStatus.PENDING_VERIFICATION);

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), PASSWORD),
                UUID.randomUUID().toString(),
                "127.0.0.11"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_PENDING_VERIFICATION));
    }

    @Test
    void disabledAccountWithWrongPasswordReturnsInvalidCredentials() {
        User user = createLoginUser(AccountStatus.DISABLED);

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), "87654321"),
                UUID.randomUUID().toString(),
                "127.0.0.12"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    @Test
    void disabledAccountWithCorrectPasswordReturnsAccountDisabled() {
        User user = createLoginUser(AccountStatus.DISABLED);

        assertThatThrownBy(() -> authenticationService.login(
                new LoginRequest(user.getEmail(), PASSWORD),
                UUID.randomUUID().toString(),
                "127.0.0.13"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_DISABLED));
    }

    private User createLoginUser(AccountStatus status) {
        User user = new User(
                "Auth",
                "Test",
                "login-" + UUID.randomUUID() + "@example.com",
                "not-used"
        );
        if (status == AccountStatus.DISABLED) {
            user.disable();
        }
        user.changePasswordHash(passwordEncoder.encode(PASSWORD));
        return userRepository.saveAndFlush(user);
    }
}
