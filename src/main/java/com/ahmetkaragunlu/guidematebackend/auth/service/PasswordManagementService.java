package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class PasswordManagementService {

    private static final String FORGOT_RATE_LIMIT_OPERATION = "forgot-password";

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureTokenService secureTokenService;
    private final EmailNormalizer emailNormalizer;
    private final PasswordPolicy passwordPolicy;
    private final AuthRateLimitService rateLimitService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final MessageSource messageSource;
    private final EmailService emailService;
    private final RefreshSessionService refreshSessionService;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String forgotPassword(ForgotPasswordRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquirePublicPermit(FORGOT_RATE_LIMIT_OPERATION, email, clientIp);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || user.getAccountStatus() != AccountStatus.ACTIVE) {
            return message("auth.forgotPassword.sent");
        }

        LocalDateTime now = localNow();
        passwordResetTokenRepository.invalidateActiveTokens(user.getId(), now);
        PasswordResetToken token = new PasswordResetToken(user, secureTokenService.generate(), now);
        passwordResetTokenRepository.save(token);
        emailService.sendPasswordResetEmail(user.getEmail(), token.getToken());
        return message("auth.forgotPassword.sent");
    }

    @Transactional
    public String resetPassword(ResetPasswordRequest request) {
        passwordPolicy.validate(request.newPassword());
        if (!Objects.equals(request.newPassword(), request.confirmPassword())) {
            throw new BusinessException(ErrorCode.PASSWORDS_DO_NOT_MATCH);
        }

        LocalDateTime now = localNow();
        PasswordResetToken token = findUsableResetTokenForUpdate(request.token(), now);
        User user = userRepository.findByIdForUpdate(token.getUser().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        user.incrementTokenVersion();
        token.markUsed(now);
        refreshSessionService.revokeAll(user);
        publishPasswordSecurityNotification(user, "PASSWORD_RESET");
        return message("auth.password.reset");
    }

    @Transactional
    public String changePassword(ChangePasswordRequest request, String principalEmail) {
        String email = emailNormalizer.normalize(principalEmail);
        User user = userRepository.findByEmailForUpdate(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new BusinessException(ErrorCode.CURRENT_PASSWORD_INCORRECT);
        }

        passwordPolicy.validate(request.newPassword());
        if (passwordEncoder.matches(request.newPassword(), user.getPassword())) {
            throw new BusinessException(ErrorCode.PASSWORD_SAME_AS_CURRENT);
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        user.incrementTokenVersion();
        refreshSessionService.revokeAll(user);
        publishPasswordSecurityNotification(user, "PASSWORD_CHANGED");
        return message("auth.password.changed");
    }

    @Transactional(readOnly = true)
    public void validateResetToken(String rawToken) {
        findUsableResetToken(rawToken, localNow());
    }

    private void publishPasswordSecurityNotification(User user, String securityEvent) {
        notificationPublisher.publish(new NotificationCommand(
                user.getId(),
                NotificationType.SECURITY_ALERT,
                null,
                Map.of("securityEvent", securityEvent)
        ));
    }

    private PasswordResetToken findUsableResetToken(String rawToken, LocalDateTime now) {
        PasswordResetToken token = passwordResetTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        validateResetTokenState(token, now);
        return token;
    }

    private PasswordResetToken findUsableResetTokenForUpdate(String rawToken, LocalDateTime now) {
        PasswordResetToken token = passwordResetTokenRepository.findByTokenForUpdate(rawToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        validateResetTokenState(token, now);
        return token;
    }

    private void validateResetTokenState(PasswordResetToken token, LocalDateTime now) {
        if (token.isUsed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }
        if (token.isExpired(now)) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }
    }

    private LocalDateTime localNow() {
        return LocalDateTime.ofInstant(clock.instant(), ZoneId.systemDefault());
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
