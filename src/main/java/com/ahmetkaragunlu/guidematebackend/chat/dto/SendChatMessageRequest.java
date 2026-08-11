package com.ahmetkaragunlu.guidematebackend.chat.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record SendChatMessageRequest(
        @NotNull(message = "{validation.chat.clientMessageId.notNull}")
        UUID clientMessageId,

        @NotBlank(message = "{validation.chat.body.notBlank}")
        @Size(max = 2000, message = "{validation.chat.body.size}")
        String body
) {
}
