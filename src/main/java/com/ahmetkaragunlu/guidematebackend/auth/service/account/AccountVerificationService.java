package com.ahmetkaragunlu.guidematebackend.auth.service.account;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ResendVerificationRequest;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.email.EmailService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.ConfirmationTokenService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AccountVerificationService {

    private static final String RESEND_RATE_LIMIT_OPERATION = "resend-verification";

    private final UserRepository userRepository;
    private final EmailNormalizer emailNormalizer;
    private final AuthRateLimitService rateLimitService;
    private final ConfirmationTokenService confirmationTokenService;
    private final MessageSource messageSource;
    private final EmailService emailService;

    @Transactional
    public void confirmAccount(String rawToken) {
        ConfirmationTokenService.UsableConfirmationToken usableToken =
                confirmationTokenService.requireUsableForUpdate(rawToken);

        User user = userRepository.findByIdForUpdate(usableToken.token().getUser().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if (user.getAccountStatus() == AccountStatus.DISABLED) {
            throw new BusinessException(ErrorCode.ACCOUNT_DISABLED);
        }
        if (user.getAccountStatus() != AccountStatus.PENDING_VERIFICATION) {
            throw new BusinessException(ErrorCode.TOKEN_ALREADY_USED);
        }

        usableToken.token().confirm(usableToken.validatedAt());
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

        String rawToken = confirmationTokenService.replaceActive(user);
        emailService.sendConfirmationEmail(user.getEmail(), rawToken);
        return message("auth.verification.resend");
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
