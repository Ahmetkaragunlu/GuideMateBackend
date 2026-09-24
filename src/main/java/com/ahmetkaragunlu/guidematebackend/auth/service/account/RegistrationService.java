package com.ahmetkaragunlu.guidematebackend.auth.service.account;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RegisterRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.ConfirmationTokenService;
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

@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailNormalizer emailNormalizer;
    private final PasswordPolicy passwordPolicy;
    private final AuthRateLimitService rateLimitService;
    private final RegistrationConflictVerifier registrationConflictVerifier;
    private final ConfirmationTokenService confirmationTokenService;
    private final MessageSource messageSource;
    private final EmailService emailService;

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

        String rawToken = confirmationTokenService.issue(user);
        emailService.sendConfirmationEmail(user.getEmail(), rawToken);
        return messageSource.getMessage(
                "auth.register.success",
                null,
                LocaleContextHolder.getLocale()
        );
    }
}
