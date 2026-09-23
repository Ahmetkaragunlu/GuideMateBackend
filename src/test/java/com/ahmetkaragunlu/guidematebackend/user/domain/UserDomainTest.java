package com.ahmetkaragunlu.guidematebackend.user.domain;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class UserDomainTest {

    @Test
    void controlsAuthenticationStateThroughIntentMethods() {
        User user = user("user@example.com");
        Role role = mock(Role.class);
        UUID avatarId = UUID.randomUUID();

        user.activate();
        user.selectRole(role);
        user.bindGoogleSubject("google-subject");
        user.changePasswordHash("new-password-hash");
        user.incrementTokenVersion();
        user.updateAvatar(avatarId);

        assertThat(user.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(user.getRole()).isSameAs(role);
        assertThat(user.isRoleSelected()).isTrue();
        assertThat(user.getGoogleSubject()).isEqualTo("google-subject");
        assertThat(user.getPassword()).isEqualTo("new-password-hash");
        assertThat(user.getTokenVersion()).isEqualTo(1);
        assertThat(user.getAvatarMediaId()).isEqualTo(avatarId);

        user.disable();
        assertThat(user.getAccountStatus()).isEqualTo(AccountStatus.DISABLED);
    }

    @Test
    void usesImmutableNormalizedEmailAsNaturalKey() {
        User first = user("same@example.com");
        User second = user("same@example.com");
        User different = user("different@example.com");

        assertThat(first).isEqualTo(second).hasSameHashCodeAs(second);
        assertThat(first).isNotEqualTo(different);
    }

    private User user(String email) {
        return new User("Domain", "Test", email, "password-hash");
    }
}
