package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;

public record ChatMessageCreatedEvent(
        ChatMessageResponse message,
        String senderUsername,
        String recipientUsername
) {
}
