package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RoleSelectionRequest;

public interface AuthService {

    String register(RegisterRequest request);

    AuthResponse login(LoginRequest request, String installationId, String clientIp);

    AuthResponse googleLogin(GoogleLoginRequest request, String installationId);

    AuthResponse refreshToken(String refreshToken, String installationId);

    AuthResponse selectRole(RoleSelectionRequest request, String principalEmail);

    String logout(String refreshToken, String principalEmail, String installationId);

    void confirmAccount(String token);

    String resendVerification(ResendVerificationRequest request, String clientIp);

    String forgotPassword(ForgotPasswordRequest request, String clientIp);

    String resetPassword(ResetPasswordRequest request);

    String changePassword(ChangePasswordRequest request, String principalEmail);

    CurrentUserResponse currentUser(String principalEmail);

    void validateResetToken(String token);
}
