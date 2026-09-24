package com.ahmetkaragunlu.guidematebackend.auth.mapper;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthResponseMapperTest {

    private final MediaReferenceMapper mediaReferenceMapper = mock(MediaReferenceMapper.class);
    private final AuthResponseMapper mapper = new AuthResponseMapper(mediaReferenceMapper);

    @Test
    void mapsCanonicalUserFieldsToAuthAndCurrentUserResponses() {
        User user = new User("Test", "User", "user@example.com", "hash");
        Role role = mock(Role.class);
        UUID avatarMediaId = UUID.randomUUID();
        MediaReferenceResponse avatar = mock(MediaReferenceResponse.class);
        when(role.getName()).thenReturn(RoleType.ROLE_GUIDE.name());
        when(mediaReferenceMapper.fromId(avatarMediaId)).thenReturn(avatar);
        user.activate();
        user.selectRole(role);
        user.updateAvatar(avatarMediaId);

        var authResponse = mapper.toAuthResponse(user, "access", "refresh", "message");
        var currentUserResponse = mapper.toCurrentUserResponse(user);

        assertThat(authResponse.email()).isEqualTo(user.getEmail());
        assertThat(authResponse.role()).isEqualTo(RoleType.ROLE_GUIDE.name());
        assertThat(authResponse.avatar()).isSameAs(avatar);
        assertThat(currentUserResponse.email()).isEqualTo(user.getEmail());
        assertThat(currentUserResponse.role()).isEqualTo(RoleType.ROLE_GUIDE.name());
        assertThat(currentUserResponse.avatar()).isSameAs(avatar);
    }
}
