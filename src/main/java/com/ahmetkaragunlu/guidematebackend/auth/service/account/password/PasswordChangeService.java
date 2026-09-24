package com.ahmetkaragunlu.guidematebackend.auth.service.account.password;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.ChangePasswordRequest;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class PasswordChangeService {

    private final UserRepository userRepository;
    private final EmailNormalizer emailNormalizer;
    private final AccountStatusPolicy accountStatusPolicy;
    private final PasswordCredentialService passwordCredentialService;
    private final MessageSource messageSource;

    @Transactional
    public String changePassword(ChangePasswordRequest request, String principalEmail) {
        String email = emailNormalizer.normalize(principalEmail);
        User user = userRepository.findByEmailForUpdate(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        passwordCredentialService.change(user, request.currentPassword(), request.newPassword());
        return messageSource.getMessage(
                "auth.password.changed",
                null,
                LocaleContextHolder.getLocale()
        );
    }
}
