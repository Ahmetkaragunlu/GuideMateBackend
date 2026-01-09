package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.auth.domain.RefreshToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.*;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.PasswordResetTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.repository.RefreshTokenRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.user.domain.AuthProvider;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final MessageSource messageSource;

    @Value("${google.client-id}")
    private String googleClientId;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    private String getMessage(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }

    @Override
    @Transactional
    public String register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new BusinessException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        User user = new User();
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setActive(false);
        user.setRoleSelected(false);
        user.setAuthProvider(AuthProvider.LOCAL);

        userRepository.save(user);

        ConfirmationToken token = new ConfirmationToken(user);
        confirmationTokenRepository.save(token);

        return getMessage("auth.register.success");
    }

    @Override
    @Transactional
    public void logout(String requestRefreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(requestRefreshToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        refreshTokenRepository.delete(token);
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        return createAuthResponse(user);
    }

    @Override
    @Transactional
    public AuthResponse googleLogin(GoogleLoginRequest request) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(request.idToken());

            if (idToken == null) {
                throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED);
            }

            GoogleIdToken.Payload payload = idToken.getPayload();
            String email = payload.getEmail();
            String firstName = (String) payload.get("given_name");
            String lastName = (String) payload.get("family_name");

            User user = userRepository.findByEmail(email).orElseGet(() -> {
                User newUser = new User();
                newUser.setEmail(email);
                newUser.setFirstName(firstName != null ? firstName : "Google");
                newUser.setLastName(lastName != null ? lastName : "User");
                newUser.setActive(true);
                newUser.setAuthProvider(AuthProvider.GOOGLE);
                newUser.setRoleSelected(false);
                return userRepository.save(newUser);
            });

            return createAuthResponse(user);

        } catch (GeneralSecurityException | IOException e) {
            log.error("Google login verification failed: {}", e.getMessage(), e);
            throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED);
        }
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(String requestRefreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(requestRefreshToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }

        User user = token.getUser();
        String newAccessToken = jwtService.generateToken(user);

        String roleName = (user.getRole() != null) ? user.getRole().getName() : null;

        return new AuthResponse(
                newAccessToken,
                token.getToken(),
                getMessage("auth.login.success"),
                user.isRoleSelected(),
                roleName
        );
    }

    @Override
    @Transactional
    public AuthResponse selectRole(RoleSelectionRequest request, String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        if (user.isRoleSelected()) {
            throw new BusinessException(ErrorCode.ROLE_ALREADY_SELECTED);
        }

        Role role = roleRepository.findByName(request.role().name())
                .orElseThrow(() -> new BusinessException(ErrorCode.ROLE_NOT_FOUND));

        user.setRole(role);
        user.setRoleSelected(true);
        return createAuthResponse(user);
    }

    private AuthResponse createAuthResponse(User user) {
        if (!user.isActive()) {
            throw new BusinessException(ErrorCode.ACCOUNT_NOT_ACTIVE);
        }

        String accessToken = jwtService.generateToken(user);
        RefreshToken refreshToken = createRefreshToken(user);

        String roleName = (user.getRole() != null) ? user.getRole().getName() : null;

        return new AuthResponse(
                accessToken,
                refreshToken.getToken(),
                getMessage("auth.login.success"),
                user.isRoleSelected(),
                roleName
        );
    }

    private RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshExpiration));
        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    @Transactional
    public String confirmAccount(String token) {
        ConfirmationToken confirmationToken = confirmationTokenRepository.findByToken(token)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));

        if (confirmationToken.isConfirmed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }

        if (confirmationToken.isExpired()) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        }

        confirmationToken.confirm();
        confirmationToken.getUser().setActive(true);

        return getMessage("auth.account.confirmed");
    }

    @Override
    @Transactional
    public String forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        if (!user.getFirstName().equalsIgnoreCase(request.firstName()) ||
                !user.getLastName().equalsIgnoreCase(request.lastName())) {
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        passwordResetTokenRepository.expireActiveTokens(user.getId(), LocalDateTime.now());

        PasswordResetToken token = new PasswordResetToken(user);
        passwordResetTokenRepository.save(token);

        return getMessage("auth.forgotPassword.sent");
    }

    @Override
    @Transactional
    public String resetPassword(ResetPasswordRequest request) {
        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new BusinessException(ErrorCode.PASSWORDS_DO_NOT_MATCH);
        }

        PasswordResetToken resetToken = passwordResetTokenRepository.findValidToken(request.token(), LocalDateTime.now())
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(request.newPassword()));

        resetToken.setUsed(true);
        resetToken.setUsedAt(LocalDateTime.now());
        refreshTokenRepository.deleteByUser(user);

        return getMessage("auth.password.reset");
    }
}