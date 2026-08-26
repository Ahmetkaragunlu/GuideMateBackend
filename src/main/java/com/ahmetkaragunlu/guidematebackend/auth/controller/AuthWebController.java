package com.ahmetkaragunlu.guidematebackend.auth.controller;

import com.ahmetkaragunlu.guidematebackend.auth.service.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.PasswordManagementService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthWebController {

    private final AccountVerificationService accountVerificationService;
    private final PasswordManagementService passwordManagementService;
    private final MessageSource messageSource;

    @GetMapping("/confirm")
    public ModelAndView confirmAccount(@RequestParam("token") String token) {
        try {
            accountVerificationService.confirmAccount(token);
            return confirmationView(true, "web.confirm.success.title", "web.confirm.success.message");
        } catch (BusinessException exception) {
            return confirmationErrorView(exception.getErrorCode());
        }
    }

    @GetMapping("/reset-password-form")
    public ModelAndView showResetPasswordForm(@RequestParam("token") String token) {
        try {
            passwordManagementService.validateResetToken(token);
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
            case TOKEN_EXPIRED -> resetView(false, "web.reset.expired.title", "web.reset.expired.message");
            case TOKEN_ALREADY_USED -> resetView(false, "web.reset.used.title", "web.reset.used.message");
            case INVALID_TOKEN -> resetView(false, "web.reset.invalid.title", "web.reset.invalid.message");
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
