package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.notification.service.device.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthSessionService {

    private final RefreshSessionService refreshSessionService;
    private final InstallationIdValidator installationIdValidator;
    private final EmailNormalizer emailNormalizer;
    private final UserRepository userRepository;
    private final DeviceRegistrationService deviceRegistrationService;
    private final AuthResponseService authResponseService;
    private final MessageSource messageSource;

    public AuthResponse refreshToken(String refreshToken, String installationId) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        RefreshSessionService.RefreshRotationResult result =
                refreshSessionService.rotate(refreshToken, validatedInstallationId);
        if (!result.isSuccessful()) {
            throw new BusinessException(result.errorCode());
        }
        return authResponseService.create(result.user(), result.rawRefreshToken(), "auth.login.success");
    }

    public String logout(String refreshToken, String principalEmail, String installationId) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        String email = emailNormalizer.normalize(principalEmail);
        refreshSessionService.revoke(refreshToken, email, validatedInstallationId);
        userRepository.findByEmail(email).ifPresent(user -> deviceRegistrationService.deactivate(
                user.getId(),
                UUID.fromString(validatedInstallationId)
        ));
        return messageSource.getMessage("auth.logout.success", null, LocaleContextHolder.getLocale());
    }
}
