package com.ahmetkaragunlu.guidematebackend.auth.service.account;

import com.ahmetkaragunlu.guidematebackend.auth.dto.request.RoleSelectionRequest;
import com.ahmetkaragunlu.guidematebackend.auth.dto.request.SelectableRole;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.auth.mapper.AuthResponseMapper;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthResponseService;
import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.user.service.AccountStatusPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticatedUserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private AccountStatusPolicy accountStatusPolicy;
    @Mock private AuthResponseService authResponseService;
    @Mock private AuthResponseMapper authResponseMapper;

    private AuthenticatedUserService service;

    @BeforeEach
    void setUp() {
        service = new AuthenticatedUserService(
                userRepository,
                roleRepository,
                new EmailNormalizer(),
                accountStatusPolicy,
                authResponseService,
                authResponseMapper
        );
    }

    @Test
    void selectsRoleOnlyForAccountWithoutExistingRole() {
        User user = activeUser();
        Role guideRole = mock(Role.class);
        AuthResponse response = mock(AuthResponse.class);
        when(guideRole.getName()).thenReturn(RoleType.ROLE_GUIDE.name());
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(roleRepository.findByName(RoleType.ROLE_GUIDE.name())).thenReturn(Optional.of(guideRole));
        when(authResponseService.create(user, null, "auth.role.selected")).thenReturn(response);

        assertThat(service.selectRole(
                new RoleSelectionRequest(SelectableRole.ROLE_GUIDE),
                user.getEmail()
        )).isSameAs(response);

        assertThat(user.hasRole(RoleType.ROLE_GUIDE)).isTrue();
        verify(accountStatusPolicy).requireActive(user);
    }

    @Test
    void mapsCurrentActiveUserFromCanonicalAccount() {
        User user = activeUser();
        CurrentUserResponse response = mock(CurrentUserResponse.class);
        when(userRepository.findByEmailWithRole(user.getEmail())).thenReturn(Optional.of(user));
        when(authResponseMapper.toCurrentUserResponse(user)).thenReturn(response);

        assertThat(service.currentUser(" USER@example.com ")).isSameAs(response);

        verify(accountStatusPolicy).requireActive(user);
    }

    private User activeUser() {
        User user = new User("Test", "User", "user@example.com", "hash");
        user.activate();
        return user;
    }
}
