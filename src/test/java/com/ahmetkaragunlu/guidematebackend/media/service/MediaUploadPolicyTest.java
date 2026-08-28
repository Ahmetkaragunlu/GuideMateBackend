package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MediaUploadPolicyTest {

    private final MediaUploadPolicy policy = new MediaUploadPolicy();

    @Test
    void allowsUserAvatarForTouristsAndGuides() {
        assertThatCode(() -> policy.requireAllowed(userWithRole(RoleType.ROLE_TOURIST), MediaPurpose.USER_AVATAR))
                .doesNotThrowAnyException();
        assertThatCode(() -> policy.requireAllowed(userWithRole(RoleType.ROLE_GUIDE), MediaPurpose.USER_AVATAR))
                .doesNotThrowAnyException();
    }

    @Test
    void keepsTourCoverGuideOnly() {
        assertThatCode(() -> policy.requireAllowed(userWithRole(RoleType.ROLE_GUIDE), MediaPurpose.TOUR_COVER))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> policy.requireAllowed(
                userWithRole(RoleType.ROLE_TOURIST),
                MediaPurpose.TOUR_COVER
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.FORBIDDEN));
    }

    private User userWithRole(RoleType roleType) {
        User user = mock(User.class);
        when(user.hasRole(roleType)).thenReturn(true);
        return user;
    }
}
