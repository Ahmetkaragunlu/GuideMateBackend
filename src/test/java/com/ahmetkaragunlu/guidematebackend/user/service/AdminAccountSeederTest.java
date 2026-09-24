package com.ahmetkaragunlu.guidematebackend.user.service;

import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.user.config.AdminAccountSeedProperties;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AdminAccountSeederTest {

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private PasswordPolicy passwordPolicy;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        roleRepository = mock(RoleRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        passwordPolicy = mock(PasswordPolicy.class);
    }

    @Test
    void keepsExistingActiveAdminWithoutCreatingDuplicate() {
        User existing = mock(User.class);
        when(existing.hasRole(RoleType.ROLE_ADMIN)).thenReturn(true);
        when(existing.getAccountStatus()).thenReturn(AccountStatus.ACTIVE);
        when(userRepository.findByEmailWithRole("admin@example.com")).thenReturn(Optional.of(existing));

        assertThatCode(() -> seeder().run(null)).doesNotThrowAnyException();

        verify(userRepository, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void rejectsSeedEmailOwnedByNonAdminAccount() {
        User existing = mock(User.class);
        when(existing.hasRole(RoleType.ROLE_ADMIN)).thenReturn(false);
        when(userRepository.findByEmailWithRole("admin@example.com")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> seeder().run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not an active admin");
    }

    @Test
    void createsActiveAdminWithEncodedPassword() throws Exception {
        Role role = mock(Role.class);
        when(role.getName()).thenReturn(RoleType.ROLE_ADMIN.name());
        when(userRepository.findByEmailWithRole("admin@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName(RoleType.ROLE_ADMIN.name())).thenReturn(Optional.of(role));
        when(passwordEncoder.encode("12345678")).thenReturn("encoded-password");

        seeder().run(null);

        ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(user.capture());
        assertThat(user.getValue().getEmail()).isEqualTo("admin@example.com");
        assertThat(user.getValue().getPassword()).isEqualTo("encoded-password");
        assertThat(user.getValue().getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(user.getValue().hasRole(RoleType.ROLE_ADMIN)).isTrue();
        verify(passwordPolicy).validate("12345678");
    }

    private AdminAccountSeeder seeder() {
        return new AdminAccountSeeder(
                userRepository,
                roleRepository,
                passwordEncoder,
                passwordPolicy,
                new EmailNormalizer(),
                new AdminAccountSeedProperties(
                        true,
                        " Admin@Example.com ",
                        "12345678",
                        "GuideMate",
                        "Admin"
                )
        );
    }
}
