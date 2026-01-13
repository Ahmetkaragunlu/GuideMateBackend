package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.*;

public interface AuthService {

    String register(RegisterRequest request, String deviceId);
    AuthResponse login(LoginRequest request, String deviceId);
    AuthResponse googleLogin(GoogleLoginRequest request, String deviceId);
    AuthResponse refreshToken(String requestRefreshToken, String deviceId);
    AuthResponse selectRole(RoleSelectionRequest request, String email, String deviceId);
    String logout(String requestRefreshToken);
    void confirmAccount(String token);
    String forgotPassword(ForgotPasswordRequest request);
    String resetPassword(ResetPasswordRequest request);
}