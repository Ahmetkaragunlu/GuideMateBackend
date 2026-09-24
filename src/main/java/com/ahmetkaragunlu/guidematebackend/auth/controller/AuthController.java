package com.ahmetkaragunlu.guidematebackend.auth.controller;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RefreshTokenRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.AuthenticatedUserService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.RegistrationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.account.password.PasswordManagementService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthSessionService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String INSTALLATION_HEADER = "X-Installation-Id";

    private final AuthenticationService authenticationService;
    private final AuthSessionService authSessionService;
    private final AuthenticatedUserService authenticatedUserService;
    private final RegistrationService registrationService;
    private final AccountVerificationService accountVerificationService;
    private final PasswordManagementService passwordManagementService;

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                registrationService.register(request, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                authenticationService.login(request, installationId, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/google")
    public ResponseEntity<AuthResponse> googleLogin(
            @Valid @RequestBody GoogleLoginRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                authenticationService.googleLogin(
                        request,
                        installationId,
                        httpRequest.getRemoteAddr()
                )
        );
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId
    ) {
        return ResponseEntity.ok(authSessionService.refreshToken(request.token(), installationId));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @Valid @RequestBody RefreshTokenRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId,
            Authentication authentication
    ) {
        return ResponseEntity.ok(
                authSessionService.logout(request.token(), authentication.getName(), installationId)
        );
    }

    @PostMapping("/select-role")
    public ResponseEntity<AuthResponse> selectRole(
            @Valid @RequestBody RoleSelectionRequest request,
            Authentication authentication
    ) {
        return ResponseEntity.ok(authenticatedUserService.selectRole(request, authentication.getName()));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> currentUser(Authentication authentication) {
        return ResponseEntity.ok(authenticatedUserService.currentUser(authentication.getName()));
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication
    ) {
        return ResponseEntity.ok(
                passwordManagementService.changePassword(request, authentication.getName())
        );
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                accountVerificationService.resendVerification(request, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                passwordManagementService.forgotPassword(request, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(passwordManagementService.resetPassword(request));
    }
}
