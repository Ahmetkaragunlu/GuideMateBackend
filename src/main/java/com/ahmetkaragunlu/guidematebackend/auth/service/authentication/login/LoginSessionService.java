package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthResponseService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginSessionService {

    private final RefreshSessionService refreshSessionService;
    private final AuthResponseService authResponseService;

    public AuthResponse complete(User user, String installationId) {
        String refreshToken = refreshSessionService.createSession(user, installationId);
        return authResponseService.create(user, refreshToken, "auth.login.success");
    }
}
