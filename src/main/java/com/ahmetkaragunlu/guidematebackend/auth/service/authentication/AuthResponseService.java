package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.mapper.AuthResponseMapper;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthResponseService {

    private final JwtService jwtService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final MessageSource messageSource;
    private final AuthResponseMapper authResponseMapper;

    public AuthResponse create(User user, String refreshToken, String messageKey) {
        accountStatusPolicy.requireActive(user);
        return authResponseMapper.toAuthResponse(
                user,
                jwtService.generateToken(user),
                refreshToken,
                messageSource.getMessage(messageKey, null, LocaleContextHolder.getLocale())
        );
    }
}
