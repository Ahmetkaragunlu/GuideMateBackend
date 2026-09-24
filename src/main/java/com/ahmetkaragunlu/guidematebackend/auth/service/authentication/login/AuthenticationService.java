package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordLoginService passwordLoginService;
    private final GoogleLoginService googleLoginService;

    public AuthResponse login(LoginRequest request, String installationId, String clientIp) {
        return passwordLoginService.login(request, installationId, clientIp);
    }

    public AuthResponse googleLogin(GoogleLoginRequest request, String installationId, String clientIp) {
        return googleLoginService.login(request, installationId, clientIp);
    }
}
