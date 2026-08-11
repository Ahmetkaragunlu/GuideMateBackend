package com.ahmetkaragunlu.guidematebackend.chat.dto;

import java.time.Instant;
import java.util.UUID;

public record ChatConversationResponse(
        UUID chatId,
        ChatParticipantResponse guide,
        ChatParticipantResponse tourist,
        ChatMessageResponse lastMessage,
        long unreadCount,
        Instant createdAt,
        Instant lastActivityAt
) {
}
