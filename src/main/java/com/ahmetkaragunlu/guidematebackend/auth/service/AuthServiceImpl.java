package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ForgotPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResetPasswordRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.service.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String RESEND_RATE_LIMIT_OPERATION = "resend-verification";
    private static final String FORGOT_RATE_LIMIT_OPERATION = "forgot-password";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SecureTokenService secureTokenService;
    private final EmailNormalizer emailNormalizer;
    private final PasswordPolicy passwordPolicy;
    private final InstallationIdValidator installationIdValidator;
    private final GoogleTokenVerifier googleTokenVerifier;
    private final RefreshSessionService refreshSessionService;
    private final AuthRateLimitService rateLimitService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final MessageSource messageSource;
    private final EmailService emailService;
    private final DeviceRegistrationService deviceRegistrationService;

    @Override
    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String register(RegisterRequest request) {
        String email = emailNormalizer.normalize(request.email());
        passwordPolicy.validate(request.password());
        if (userRepository.existsByEmail(email)) {
            throw new BusinessException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        User user = new User();
        user.setFirstName(request.firstName().strip());
        user.setLastName(request.lastName().strip());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setAccountStatus(AccountStatus.PENDING_VERIFICATION);
        user.setRoleSelected(false);

        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.EMAIL_ALREADY_EXISTS, exception);
        }

        ConfirmationToken token = createConfirmationToken(user);
        emailService.sendConfirmationEmail(user.getEmail(), token.getToken());
        return message("auth.register.success");
    }

    @Override
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
        } catch (BadCredentialsException exception) {
            rateLimitService.recordLoginFailure(email, clientIp);
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        } catch (AuthenticationException exception) {
            rateLimitService.recordLoginFailure(email, clientIp);
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        rateLimitService.recordLoginSuccess(email, clientIp);
        User user = findUser(email);
        String refreshToken = refreshSessionService.createSession(user, validatedInstallationId);
        return authResponse(user, refreshToken, "auth.login.success");
    }

    @Override
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

    @Override
    public AuthResponse refreshToken(String refreshToken, String installationId) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        RefreshSessionService.RefreshRotationResult result =
                refreshSessionService.rotate(refreshToken, validatedInstallationId);
        if (!result.isSuccessful()) {
            throw new BusinessException(result.errorCode());
        }
        return authResponse(result.user(), result.rawRefreshToken(), "auth.login.success");
    }

    @Override
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

    @Override
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

    @Override
    @Transactional
    public void confirmAccount(String rawToken) {
        ConfirmationToken token = confirmationTokenRepository.findByTokenForUpdate(rawToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        if (token.isConfirmed() || token.isUsed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }
        if (token.isExpired()) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }

        User user = userRepository.findByIdForUpdate(token.getUser().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if (user.getAccountStatus() == AccountStatus.DISABLED) {
            throw new BusinessException(ErrorCode.ACCOUNT_DISABLED);
        }
        if (user.getAccountStatus() != AccountStatus.PENDING_VERIFICATION) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }

        token.confirm();
        user.activate();
    }

    @Override
    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String resendVerification(ResendVerificationRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquirePublicPermit(RESEND_RATE_LIMIT_OPERATION, email, clientIp);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null
                || user.getAccountStatus() != AccountStatus.PENDING_VERIFICATION) {
            return message("auth.verification.resend");
        }

        confirmationTokenRepository.invalidateActiveTokens(user.getId(), LocalDateTime.now());
        ConfirmationToken token = createConfirmationToken(user);
        emailService.sendConfirmationEmail(user.getEmail(), token.getToken());
        return message("auth.verification.resend");
    }

    @Override
    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String forgotPassword(ForgotPasswordRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquirePublicPermit(FORGOT_RATE_LIMIT_OPERATION, email, clientIp);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null
                || user.getAccountStatus() != AccountStatus.ACTIVE) {
            return message("auth.forgotPassword.sent");
        }

        passwordResetTokenRepository.invalidateActiveTokens(user.getId(), LocalDateTime.now());
        PasswordResetToken token = new PasswordResetToken(user, secureTokenService.generate());
        passwordResetTokenRepository.save(token);
        emailService.sendPasswordResetEmail(user.getEmail(), token.getToken());
        return message("auth.forgotPassword.sent");
    }

    @Override
    @Transactional
    public String resetPassword(ResetPasswordRequest request) {
        passwordPolicy.validate(request.newPassword());
        if (!Objects.equals(request.newPassword(), request.confirmPassword())) {
            throw new BusinessException(ErrorCode.PASSWORDS_DO_NOT_MATCH);
        }

        PasswordResetToken token = findUsableResetTokenForUpdate(request.token());
        User user = userRepository.findByIdForUpdate(token.getUser().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        user.incrementTokenVersion();
        token.markUsed();
        refreshSessionService.revokeAll(user);
        return message("auth.password.reset");
    }

    @Override
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
        return message("auth.password.changed");
    }

    @Override
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

    @Override
    @Transactional(readOnly = true)
    public void validateResetToken(String rawToken) {
        findUsableResetToken(rawToken);
    }

    private ConfirmationToken createConfirmationToken(User user) {
        ConfirmationToken token = new ConfirmationToken(user, secureTokenService.generate());
        return confirmationTokenRepository.save(token);
    }

    private PasswordResetToken findUsableResetToken(String rawToken) {
        PasswordResetToken token = passwordResetTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        validateResetTokenState(token);
        return token;
    }

    private PasswordResetToken findUsableResetTokenForUpdate(String rawToken) {
        PasswordResetToken token = passwordResetTokenRepository.findByTokenForUpdate(rawToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        validateResetTokenState(token);
        return token;
    }

    private void validateResetTokenState(PasswordResetToken token) {
        if (token.isUsed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }
        if (token.isExpired()) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }
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
