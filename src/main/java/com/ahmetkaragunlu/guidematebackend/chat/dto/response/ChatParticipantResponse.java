package com.ahmetkaragunlu.guidematebackend.chat.dto.response;

public record ChatParticipantResponse(
        Long userId,
        String displayName,
        String avatarUrl
) {
}
