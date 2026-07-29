package com.ahmetkaragunlu.guidematebackend.auth.controller;

import com.ahmetkaragunlu.guidematebackend.auth.dto.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RefreshTokenRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.AuthService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String INSTALLATION_HEADER = "X-Installation-Id";

    private final AuthService authService;
    private final MessageSource messageSource;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                authService.login(request, installationId, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/google")
    public ResponseEntity<AuthResponse> googleLogin(
            @Valid @RequestBody GoogleLoginRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId
    ) {
        return ResponseEntity.ok(authService.googleLogin(request, installationId));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId
    ) {
        return ResponseEntity.ok(authService.refreshToken(request.token(), installationId));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @Valid @RequestBody RefreshTokenRequest request,
            @RequestHeader(INSTALLATION_HEADER) String installationId,
            Authentication authentication
    ) {
        return ResponseEntity.ok(
                authService.logout(request.token(), authentication.getName(), installationId)
        );
    }

    @PostMapping("/select-role")
    public ResponseEntity<AuthResponse> selectRole(
            @Valid @RequestBody RoleSelectionRequest request,
            Authentication authentication
    ) {
        return ResponseEntity.ok(authService.selectRole(request, authentication.getName()));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> currentUser(Authentication authentication) {
        return ResponseEntity.ok(authService.currentUser(authentication.getName()));
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication
    ) {
        return ResponseEntity.ok(
                authService.changePassword(request, authentication.getName())
        );
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                authService.resendVerification(request, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(
                authService.forgotPassword(request, httpRequest.getRemoteAddr())
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(request));
    }

    @GetMapping("/confirm")
    public ModelAndView confirmAccount(@RequestParam("token") String token) {
        try {
            authService.confirmAccount(token);
            return confirmationView(true, "web.confirm.success.title", "web.confirm.success.message");
        } catch (BusinessException exception) {
            return confirmationErrorView(exception.getErrorCode());
        }
    }

    @GetMapping("/reset-password-form")
    public ModelAndView showResetPasswordForm(@RequestParam("token") String token) {
        try {
            authService.validateResetToken(token);
            ModelAndView view = resetView(true, "web.reset.title", "web.reset.instructions");
            view.addObject("token", token);
            return view;
        } catch (BusinessException exception) {
            return resetErrorView(exception.getErrorCode());
        }
    }

    private ModelAndView confirmationErrorView(ErrorCode errorCode) {
        return switch (errorCode) {
            case TOKEN_EXPIRED ->
                    confirmationView(false, "web.confirm.expired.title", "web.confirm.expired.message");
            case TOKEN_ALREADY_USED ->
                    confirmationView(false, "web.confirm.used.title", "web.confirm.used.message");
            case INVALID_TOKEN ->
                    confirmationView(false, "web.confirm.invalid.title", "web.confirm.invalid.message");
            case ACCOUNT_DISABLED ->
                    confirmationView(false, "web.confirm.disabled.title", "web.confirm.disabled.message");
            default -> throw new BusinessException(errorCode);
        };
    }

    private ModelAndView resetErrorView(ErrorCode errorCode) {
        return switch (errorCode) {
            case TOKEN_EXPIRED ->
                    resetView(false, "web.reset.expired.title", "web.reset.expired.message");
            case TOKEN_ALREADY_USED ->
                    resetView(false, "web.reset.used.title", "web.reset.used.message");
            case INVALID_TOKEN ->
                    resetView(false, "web.reset.invalid.title", "web.reset.invalid.message");
            default -> throw new BusinessException(errorCode);
        };
    }

    private ModelAndView confirmationView(boolean success, String titleKey, String messageKey) {
        ModelAndView view = new ModelAndView("email-confirmation");
        view.addObject("success", success);
        view.addObject("title", message(titleKey));
        view.addObject("message", message(messageKey));
        return view;
    }

    private ModelAndView resetView(boolean validToken, String titleKey, String messageKey) {
        ModelAndView view = new ModelAndView("reset-password");
        view.addObject("validToken", validToken);
        view.addObject("title", message(titleKey));
        view.addObject("message", message(messageKey));
        return view;
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
