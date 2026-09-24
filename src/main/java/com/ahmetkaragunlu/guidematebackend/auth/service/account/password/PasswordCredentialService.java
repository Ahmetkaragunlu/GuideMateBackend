package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class PasswordCredentialService {

    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final RefreshSessionService refreshSessionService;
    private final NotificationPublisher notificationPublisher;

    public void validateNewPassword(String rawPassword) {
        passwordPolicy.validate(rawPassword);
    }

    public void reset(
            User user,
            PasswordResetToken token,
            Instant tokenValidatedAt,
            String newPassword
    ) {
        user.changePasswordHash(passwordEncoder.encode(newPassword));
        user.incrementTokenVersion();
        token.markUsed(tokenValidatedAt);
        refreshSessionService.revokeAll(user);
        publishSecurityNotification(user, "PASSWORD_RESET");
    }

    public void change(User user, String currentPassword, String newPassword) {
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new BusinessException(ErrorCode.CURRENT_PASSWORD_INCORRECT);
        }

        passwordPolicy.validate(newPassword);
        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new BusinessException(ErrorCode.PASSWORD_SAME_AS_CURRENT);
        }

        user.changePasswordHash(passwordEncoder.encode(newPassword));
        user.incrementTokenVersion();
        refreshSessionService.revokeAll(user);
        publishSecurityNotification(user, "PASSWORD_CHANGED");
    }

    private void publishSecurityNotification(User user, String securityEvent) {
        notificationPublisher.publish(new NotificationCommand(
                user.getId(),
                NotificationType.SECURITY_ALERT,
                null,
                Map.of("securityEvent", securityEvent)
        ));
    }
}
