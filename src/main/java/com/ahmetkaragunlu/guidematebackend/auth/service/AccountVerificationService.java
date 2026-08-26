package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.dto.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.repository.ConfirmationTokenRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SecureTokenService;
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
import java.time.LocalDateTime;
import java.time.ZoneId;

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
    private final MessageSource messageSource;
    private final EmailService emailService;
    private final Clock clock;

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

        ConfirmationToken token = createConfirmationToken(user, localNow());
        emailService.sendConfirmationEmail(user.getEmail(), token.getToken());
        return message("auth.register.success");
    }

    @Transactional
    public void confirmAccount(String rawToken) {
        ConfirmationToken token = confirmationTokenRepository.findByTokenForUpdate(rawToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_TOKEN));
        LocalDateTime now = localNow();
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

    @Transactional(noRollbackFor = EmailDeliveryException.class)
    public String resendVerification(ResendVerificationRequest request, String clientIp) {
        String email = emailNormalizer.normalize(request.email());
        rateLimitService.acquirePublicPermit(RESEND_RATE_LIMIT_OPERATION, email, clientIp);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || user.getAccountStatus() != AccountStatus.PENDING_VERIFICATION) {
            return message("auth.verification.resend");
        }

        LocalDateTime now = localNow();
        confirmationTokenRepository.invalidateActiveTokens(user.getId(), now);
        ConfirmationToken token = createConfirmationToken(user, now);
        emailService.sendConfirmationEmail(user.getEmail(), token.getToken());
        return message("auth.verification.resend");
    }

    private ConfirmationToken createConfirmationToken(User user, LocalDateTime now) {
        ConfirmationToken token = new ConfirmationToken(user, secureTokenService.generate(), now);
        return confirmationTokenRepository.save(token);
    }

    private LocalDateTime localNow() {
        return LocalDateTime.ofInstant(clock.instant(), ZoneId.systemDefault());
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
