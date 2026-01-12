package com.ahmetkaragunlu.guidematebackend.auth.controller;

import com.ahmetkaragunlu.guidematebackend.auth.dto.*;
import com.ahmetkaragunlu.guidematebackend.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestHeader("X-Device-Id") String deviceId
    ) {
        return ResponseEntity.ok(authService.register(request, deviceId));
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader("X-Device-Id") String deviceId
    ) {
        return ResponseEntity.ok(authService.login(request, deviceId));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            @RequestHeader("X-Device-Id") String deviceId
    ) {
        return ResponseEntity.ok(authService.refreshToken(request.token(), deviceId));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.logout(request.token()));
    }

    @PostMapping("/google")
    public ResponseEntity<AuthResponse> googleLogin(
            @Valid @RequestBody GoogleLoginRequest request,
            @RequestHeader("X-Device-Id") String deviceId
    ) {
        return ResponseEntity.ok(authService.googleLogin(request, deviceId));
    }

    @PostMapping("/select-role")
    public ResponseEntity<AuthResponse> selectRole(
            @Valid @RequestBody RoleSelectionRequest request,
            @RequestHeader("X-Device-Id") String deviceId
    ) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return ResponseEntity.ok(authService.selectRole(request, email, deviceId));
    }

    @GetMapping("/confirm")
    public ResponseEntity<String> confirmAccount(@RequestParam("token") String token) {
        return ResponseEntity.ok(authService.confirmAccount(token));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        return ResponseEntity.ok(authService.forgotPassword(request));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(request));
    }
}