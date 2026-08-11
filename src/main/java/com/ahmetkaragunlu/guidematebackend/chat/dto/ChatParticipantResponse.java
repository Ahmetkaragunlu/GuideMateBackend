package com.ahmetkaragunlu.guidematebackend.chat.dto;

public record ChatParticipantResponse(
        Long userId,
        String displayName,
        String avatarUrl
) {
}
