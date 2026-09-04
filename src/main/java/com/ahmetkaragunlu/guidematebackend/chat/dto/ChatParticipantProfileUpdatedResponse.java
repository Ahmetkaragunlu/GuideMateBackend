package com.ahmetkaragunlu.guidematebackend.chat.dto;

public record ChatParticipantProfileUpdatedResponse(
        Long userId,
        String avatarUrl
) {
}
