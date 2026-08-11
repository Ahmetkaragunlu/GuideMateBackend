package com.ahmetkaragunlu.guidematebackend.chat.dto;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record ChatMessagePageResponse(
        List<ChatMessageResponse> content,
        UUID nextCursor,
        boolean hasNext
) {
    public ChatMessagePageResponse {
        content = List.copyOf(Objects.requireNonNull(content, "content must not be null"));
    }
}
