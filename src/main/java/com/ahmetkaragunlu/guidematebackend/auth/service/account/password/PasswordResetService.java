package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.PasswordResetTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final String FORGOT_RATE_LIMIT_OPERATION = "forgot-password";

    private final UserRepository userRepository;
    private final EmailNormalizer emailNormalizer;
    private final AuthRateLimitService rateLimitService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final PasswordResetTokenService passwordResetTokenService;
    private final PasswordCredentialService passwordCredentialService;
    private final MessageSource messageSource;
    private final EmailService emailService;

    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String forgotPassword(ForgotPasswordRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquirePublicPermit(FORGOT_RATE_LIMIT_OPERATION, email, clientIp);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || user.getAccountStatus() != AccountStatus.ACTIVE) {
            return message("auth.forgotPassword.sent");
        }

        String rawToken = passwordResetTokenService.replaceActive(user);
        emailService.sendPasswordResetEmail(user.getEmail(), rawToken);
        return message("auth.forgotPassword.sent");
    }

    @Transactional
    public String resetPassword(ResetPasswordRequest request) {
        passwordCredentialService.validateNewPassword(request.newPassword());
        if (!Objects.equals(request.newPassword(), request.confirmPassword())) {
            throw new BusinessException(ErrorCode.PASSWORDS_DO_NOT_MATCH);
        }

        PasswordResetTokenService.UsablePasswordResetToken usableToken =
                passwordResetTokenService.requireUsableForUpdate(request.token());
        User user = userRepository.findByIdForUpdate(usableToken.token().getUser().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        passwordCredentialService.reset(
                user,
                usableToken.token(),
                usableToken.validatedAt(),
                request.newPassword()
        );
        return message("auth.password.reset");
    }

    @Transactional(readOnly = true)
    public void validateResetToken(String rawToken) {
        passwordResetTokenService.requireUsable(rawToken);
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
