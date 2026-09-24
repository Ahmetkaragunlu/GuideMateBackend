package com.ahmetkaragunlu.guidematebackend.auth.service.account;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.mapper.AuthResponseMapper;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthResponseService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthenticatedUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final EmailNormalizer emailNormalizer;
    private final AccountStatusPolicy accountStatusPolicy;
    private final AuthResponseService authResponseService;
    private final AuthResponseMapper authResponseMapper;

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
        user.selectRole(role);
        return authResponseService.create(user, null, "auth.role.selected");
    }

    @Transactional(readOnly = true)
    public CurrentUserResponse currentUser(String principalEmail) {
        User user = userRepository.findByEmailWithRole(emailNormalizer.normalize(principalEmail))
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        accountStatusPolicy.requireActive(user);
        return authResponseMapper.toCurrentUserResponse(user);
    }
}
