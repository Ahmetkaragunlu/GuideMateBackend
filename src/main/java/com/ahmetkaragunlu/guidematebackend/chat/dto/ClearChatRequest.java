package com.ahmetkaragunlu.guidematebackend.chat.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ClearChatRequest(
        @NotNull UUID clientRequestId
) {
}
