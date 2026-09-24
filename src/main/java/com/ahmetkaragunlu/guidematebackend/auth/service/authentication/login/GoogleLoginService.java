package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.GoogleLoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.GoogleTokenVerifier;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.InstallationIdValidator;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class GoogleLoginService {

    private final UserRepository userRepository;
    private final EmailNormalizer emailNormalizer;
    private final InstallationIdValidator installationIdValidator;
    private final GoogleTokenVerifier googleTokenVerifier;
    private final AuthRateLimitService rateLimitService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final LoginSessionService loginSessionService;

    @Transactional
    public AuthResponse login(GoogleLoginRequest request, String installationId, String clientIp) {
        String validatedInstallationId = installationIdValidator.validate(installationId);
        rateLimitService.acquireGoogleLoginPermit(validatedInstallationId, clientIp);
        GoogleTokenVerifier.GoogleIdentity identity = googleTokenVerifier.verify(request.idToken());
        String email = emailNormalizer.normalize(identity.email());

        User user = userRepository.findByGoogleSubjectWithRole(identity.subject()).orElse(null);
        if (user == null) {
            user = userRepository.findByEmailForUpdate(email)
                    .orElseThrow(() -> new BusinessException(ErrorCode.GOOGLE_ACCOUNT_NOT_FOUND));
        }
        accountStatusPolicy.requireActive(user);
        bindGoogleSubject(user, identity.subject());
        return loginSessionService.complete(user, validatedInstallationId);
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
            user.bindGoogleSubject(googleSubject);
            try {
                userRepository.saveAndFlush(user);
            } catch (DataIntegrityViolationException exception) {
                throw new BusinessException(ErrorCode.GOOGLE_ACCOUNT_MISMATCH, exception);
            }
        }
    }
}
