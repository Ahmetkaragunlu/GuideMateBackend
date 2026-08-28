package com.ahmetkaragunlu.guidematebackend.profile.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record UpdateUserAvatarRequest(
        @NotNull(message = "{validation.user.avatarMediaId.notNull}")
        UUID avatarMediaId
) {
}
