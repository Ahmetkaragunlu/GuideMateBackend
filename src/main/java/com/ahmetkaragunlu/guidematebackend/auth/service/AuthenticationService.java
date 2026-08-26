package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.dto.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.notification.service.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailNormalizer emailNormalizer;
    private final InstallationIdValidator installationIdValidator;
    private final GoogleTokenVerifier googleTokenVerifier;
    private final RefreshSessionService refreshSessionService;
    private final AuthRateLimitService rateLimitService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final MessageSource messageSource;
    private final DeviceRegistrationService deviceRegistrationService;

    @Transactional
    public AuthResponse login(LoginRequest request, String installationId, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        String validatedInstallationId = installationIdValidator.validate(installationId);
        rateLimitService.checkLoginAllowed(email, clientIp);

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, request.password())
            );
        } catch (DisabledException exception) {
            User inactiveUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_CREDENTIALS));
            ErrorCode errorCode = accountStatusPolicy.accessError(inactiveUser)
                    .orElse(ErrorCode.INVALID_CREDENTIALS);
            throw new BusinessException(errorCode);
        } catch (AuthenticationException exception) {
            rateLimitService.recordLoginFailure(email, clientIp);
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        rateLimitService.recordLoginSuccess(email, clientIp);
        User user = findUser(email);
        String refreshToken = refreshSessionService.createSession(user, validatedInstallationId);
        return authResponse(user, refreshToken, "auth.login.success");
    }

    @Transactional
    public AuthResponse googleLogin(GoogleLoginRequest request, String installationId) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        GoogleTokenVerifier.GoogleIdentity identity = googleTokenVerifier.verify(request.idToken());
        String email = emailNormalizer.normalize(identity.email());

        User user = userRepository.findByGoogleSubjectWithRole(identity.subject()).orElse(null);
        if (user == null) {
            user = userRepository.findByEmailForUpdate(email)
                    .orElseThrow(() -> new BusinessException(ErrorCode.GOOGLE_ACCOUNT_NOT_FOUND));
        }
        accountStatusPolicy.requireActive(user);
        bindGoogleSubject(user, identity.subject());

        String refreshToken = refreshSessionService.createSession(user, validatedInstallationId);
        return authResponse(user, refreshToken, "auth.login.success");
    }

    public AuthResponse refreshToken(String refreshToken, String installationId) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        RefreshSessionService.RefreshRotationResult result =
                refreshSessionService.rotate(refreshToken, validatedInstallationId);
        if (!result.isSuccessful()) {
            throw new BusinessException(result.errorCode());
        }
        return authResponse(result.user(), result.rawRefreshToken(), "auth.login.success");
    }

    @Transactional
    public AuthResponse selectRole(RoleSelectionRequest request, String principalEmail) {
        String email = emailNormalizer.normalize(principalEmail);
        User user = userRepository.findByEmailForUpdate(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        if (user.isRoleSelected()) {
            throw new BusinessException(ErrorCode.ROLE_ALREADY_SELECTED);
        }

        String roleName = request.role().toInternalRole().name();
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new BusinessException(ErrorCode.ROLE_NOT_FOUND));
        user.setRole(role);
        user.setRoleSelected(true);
        return authResponse(user, null, "auth.role.selected");
    }

    public String logout(String refreshToken, String principalEmail, String installationId) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        String email = emailNormalizer.normalize(principalEmail);
        refreshSessionService.revoke(refreshToken, email, validatedInstallationId);
        userRepository.findByEmail(email).ifPresent(user -> deviceRegistrationService.deactivate(
                user.getId(),
                UUID.fromString(validatedInstallationId)
        ));
        return message("auth.logout.success");
    }

    @Transactional(readOnly = true)
    public CurrentUserResponse currentUser(String principalEmail) {
        User user = findUser(emailNormalizer.normalize(principalEmail));
        accountStatusPolicy.requireActive(user);
        return new CurrentUserResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isRoleSelected(),
                roleName(user)
        );
    }

    private void bindGoogleSubject(User user, String googleSubject) {
        if (user.getGoogleSubject() != null && !user.getGoogleSubject().equals(googleSubject)) {
            throw new BusinessException(ErrorCode.GOOGLE_ACCOUNT_MISMATCH);
        }

        User linkedUser = userRepository.findByGoogleSubject(googleSubject).orElse(null);
        if (linkedUser != null && !linkedUser.getId().equals(user.getId())) {
            throw new BusinessException(ErrorCode.GOOGLE_ACCOUNT_MISMATCH);
        }

        if (user.getGoogleSubject() == null) {
            user.setGoogleSubject(googleSubject);
            try {
                userRepository.saveAndFlush(user);
            } catch (DataIntegrityViolationException exception) {
                throw new BusinessException(ErrorCode.GOOGLE_ACCOUNT_MISMATCH, exception);
            }
        }
    }

    private AuthResponse authResponse(User user, String refreshToken, String messageKey) {
        accountStatusPolicy.requireActive(user);
        return new AuthResponse(
                jwtService.generateToken(user),
                refreshToken,
                message(messageKey),
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isRoleSelected(),
                roleName(user)
        );
    }

    private User findUser(String normalizedEmail) {
        return userRepository.findByEmailWithRole(normalizedEmail)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
    }

    private String roleName(User user) {
        return user.getRole() == null ? null : user.getRole().getName();
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
