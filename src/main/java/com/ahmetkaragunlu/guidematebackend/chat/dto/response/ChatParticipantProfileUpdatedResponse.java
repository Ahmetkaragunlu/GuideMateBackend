package com.ahmetkaragunlu.guidematebackend.chat.dto.response;

public record ChatParticipantProfileUpdatedResponse(
        Long userId,
        String avatarUrl
) {
}
