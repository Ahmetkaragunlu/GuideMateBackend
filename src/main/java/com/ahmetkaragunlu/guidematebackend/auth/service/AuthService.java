package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.*;

public interface AuthService {
    String register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(String refreshToken);

    void logout(String refreshToken);

    String confirmAccount(String token);

    String forgotPassword(ForgotPasswordRequest request);

    String resetPassword(ResetPasswordRequest request);

    AuthResponse googleLogin(GoogleLoginRequest request);

    AuthResponse selectRole(RoleSelectionRequest request, String email);
}