package com.ahmetkaragunlu.guidematebackend.profile.service;

public record UserAvatarUpdatedEvent(
        Long userId,
        String avatarUrl
) {
}
