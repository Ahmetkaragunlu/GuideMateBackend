package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.springframework.stereotype.Component;

@Component
public class MediaUploadPolicy {

    public void requireAllowed(User user, MediaPurpose purpose) {
        boolean userAvatar = purpose == MediaPurpose.USER_AVATAR
                && (user.hasRole(RoleType.ROLE_TOURIST) || user.hasRole(RoleType.ROLE_GUIDE));
        boolean tourCover = purpose == MediaPurpose.TOUR_COVER
                && user.hasRole(RoleType.ROLE_GUIDE);
        if (!userAvatar && !tourCover) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
    }
}
