package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResetPasswordRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PasswordManagementService {

    private final PasswordResetService passwordResetService;
    private final PasswordChangeService passwordChangeService;

    public String forgotPassword(ForgotPasswordRequest request, String clientIp) {
        return passwordResetService.forgotPassword(request, clientIp);
    }

    public String resetPassword(ResetPasswordRequest request) {
        return passwordResetService.resetPassword(request);
    }

    public String changePassword(ChangePasswordRequest request, String principalEmail) {
        return passwordChangeService.changePassword(request, principalEmail);
    }

    public void validateResetToken(String rawToken) {
        passwordResetService.validateResetToken(rawToken);
    }
}
