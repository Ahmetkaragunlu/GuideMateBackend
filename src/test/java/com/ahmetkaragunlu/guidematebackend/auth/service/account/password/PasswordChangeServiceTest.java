package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;

import java.util.Locale;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordChangeServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private EmailNormalizer emailNormalizer;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private PasswordCredentialService passwordCredentialService;
    @Mock private MessageSource messageSource;

    private PasswordChangeService service;

    @BeforeEach
    void setUp() {
        service = new PasswordChangeService(
                userRepository,
                emailNormalizer,
                accountStatusPolicy,
                passwordCredentialService,
                messageSource
        );
    }

    @Test
    void changesCredentialsForLockedActiveUser() {
        User user = org.mockito.Mockito.mock(User.class);
        when(emailNormalizer.normalize(" User@example.com ")).thenReturn("user@example.com");
        when(userRepository.findByEmailForUpdate("user@example.com")).thenReturn(Optional.of(user));
        when(messageSource.getMessage("auth.password.changed", null, Locale.getDefault()))
                .thenReturn("changed");
        ChangePasswordRequest request = new ChangePasswordRequest("12345678", "87654321");

        String result = service.changePassword(request, " User@example.com ");

        assertThat(result).isEqualTo("changed");
        verify(accountStatusPolicy).requireActive(user);
        verify(passwordCredentialService).change(user, "12345678", "87654321");
    }
}
