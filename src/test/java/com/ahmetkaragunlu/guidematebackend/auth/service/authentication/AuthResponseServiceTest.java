package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.mapper.AuthResponseMapper;
import com.ahmetkaragunlu.guidematebackend.common.security.jwt.JwtService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthResponseServiceTest {

    @Mock private JwtService jwtService;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private MessageSource messageSource;
    @Mock private AuthResponseMapper authResponseMapper;
    @InjectMocks private AuthResponseService service;

    @Test
    void createsResponseOnlyForActiveAccount() {
        User user = mock(User.class);
        AuthResponse response = mock(AuthResponse.class);
        when(jwtService.generateToken(user)).thenReturn("access-token");
        when(messageSource.getMessage(eq("auth.login.success"), isNull(), any(Locale.class)))
                .thenReturn("success");
        when(authResponseMapper.toAuthResponse(
                user,
                "access-token",
                "refresh-token",
                "success"
        )).thenReturn(response);

        assertThat(service.create(user, "refresh-token", "auth.login.success")).isSameAs(response);

        verify(accountStatusPolicy).requireActive(user);
    }
}
