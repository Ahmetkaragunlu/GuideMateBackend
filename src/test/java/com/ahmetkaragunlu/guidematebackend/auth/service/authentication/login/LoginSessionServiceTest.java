package com.ahmetkaragunlu.guidematebackend.auth.service.authentication.login;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.service.authentication.AuthResponseService;
import com.ahmetkaragunlu.guidematebackend.auth.service.token.RefreshSessionService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LoginSessionServiceTest {

    @Test
    void createsRefreshSessionBeforeBuildingAuthResponse() {
        RefreshSessionService refreshSessionService = mock(RefreshSessionService.class);
        AuthResponseService authResponseService = mock(AuthResponseService.class);
        LoginSessionService service = new LoginSessionService(refreshSessionService, authResponseService);
        User user = mock(User.class);
        AuthResponse expected = mock(AuthResponse.class);
        when(refreshSessionService.createSession(user, "installation-id")).thenReturn("refresh-token");
        when(authResponseService.create(user, "refresh-token", "auth.login.success"))
                .thenReturn(expected);

        AuthResponse result = service.complete(user, "installation-id");

        assertThat(result).isSameAs(expected);
        verify(refreshSessionService).createSession(user, "installation-id");
    }
}
