package com.ahmetkaragunlu.guidematebackend.chat.dto;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessageDeliveryStatus;

import java.time.Instant;
import java.util.UUID;

public record ChatMessageResponse(
        UUID messageId,
        UUID chatId,
        Long senderId,
        UUID clientMessageId,
        String body,
        Instant sentAt,
        ChatMessageDeliveryStatus deliveryStatus
) {
}
