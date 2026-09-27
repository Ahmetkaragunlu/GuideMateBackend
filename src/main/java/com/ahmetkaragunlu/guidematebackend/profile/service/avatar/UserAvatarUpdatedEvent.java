package com.ahmetkaragunlu.guidematebackend.profile.service.avatar;

public record UserAvatarUpdatedEvent(
        Long userId,
        String avatarUrl
) {
}
