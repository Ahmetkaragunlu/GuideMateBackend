package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AccountVerificationService {

    private static final String RESEND_RATE_LIMIT_OPERATION = "resend-verification";

    private final UserRepository userRepository;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureTokenService secureTokenService;
    private final EmailNormalizer emailNormalizer;
    private final PasswordPolicy passwordPolicy;
    private final AuthRateLimitService rateLimitService;
    private final RegistrationConflictVerifier registrationConflictVerifier;
    private final MessageSource messageSource;
    private final EmailService emailService;
    private final Clock clock;

    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String register(RegisterRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquireRegistrationPermit(email, clientIp);
        passwordPolicy.validate(request.password());
        User existingUser = userRepository.findByEmail(email).orElse(null);
        if (existingUser != null) {
            ErrorCode errorCode = existingUser.getAccountStatus() == AccountStatus.PENDING_VERIFICATION
                    ? ErrorCode.ACCOUNT_PENDING_VERIFICATION
                    : ErrorCode.EMAIL_ALREADY_EXISTS;
            throw new BusinessException(errorCode);
        }

        User user = new User(
                request.firstName().strip(),
                request.lastName().strip(),
                email,
                passwordEncoder.encode(request.password())
        );

        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            if (registrationConflictVerifier.emailExists(email)) {
                throw new BusinessException(ErrorCode.EMAIL_ALREADY_EXISTS, exception);
            }
            throw exception;
        }

        String rawToken = createConfirmationToken(user, clock.instant());
        emailService.sendConfirmationEmail(user.getEmail(), rawToken);
        return message("auth.register.success");
    }

    @Transactional
    public void confirmAccount(String rawToken) {
        ConfirmationToken token = confirmationTokenRepository
                .findByTokenHashForUpdate(secureTokenService.hash(rawToken))
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        Instant now = clock.instant();
        if (token.isConfirmed() || token.isUsed()) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }
        if (token.isExpired(now)) {
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

        token.confirm(now);
        user.activate();
    }

    @Transactional
    public String resendVerification(ResendVerificationRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquirePublicPermit(RESEND_RATE_LIMIT_OPERATION, email, clientIp);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || user.getAccountStatus() != AccountStatus.PENDING_VERIFICATION) {
            return message("auth.verification.resend");
        }

        Instant now = clock.instant();
        confirmationTokenRepository.invalidateActiveTokens(user.getId(), now);
        String rawToken = createConfirmationToken(user, now);
        emailService.sendConfirmationEmail(user.getEmail(), rawToken);
        return message("auth.verification.resend");
    }

    private String createConfirmationToken(User user, Instant now) {
        String rawToken = secureTokenService.generate();
        confirmationTokenRepository.save(
                new ConfirmationToken(user, secureTokenService.hash(rawToken), now)
        );
        return rawToken;
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
