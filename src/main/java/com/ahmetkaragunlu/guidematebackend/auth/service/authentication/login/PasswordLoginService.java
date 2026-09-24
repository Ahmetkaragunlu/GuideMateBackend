package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.LoginRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthRateLimitService;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.InstallationIdValidator;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class PasswordLoginService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final EmailNormalizer emailNormalizer;
    private final InstallationIdValidator installationIdValidator;
    private final AuthRateLimitService rateLimitService;
    private final AccountStatusPolicy accountStatusPolicy;
    private final LoginSessionService loginSessionService;

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
            if (!passwordEncoder.matches(request.password(), inactiveUser.getPassword())) {
                rateLimitService.recordLoginFailure(email, clientIp);
                throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
            }
            ErrorCode errorCode = accountStatusPolicy.accessError(inactiveUser)
                    .orElse(ErrorCode.INVALID_CREDENTIALS);
            throw new BusinessException(errorCode);
        } catch (AuthenticationException exception) {
            rateLimitService.recordLoginFailure(email, clientIp);
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        rateLimitService.recordLoginSuccess(email, clientIp);
        User user = userRepository.findByEmailWithRole(email)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        return loginSessionService.complete(user, validatedInstallationId);
    }
}
