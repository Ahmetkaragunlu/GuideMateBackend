package com.ahmetkaragunlu.guidematebackend.chat.dto.request;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ClearChatRequest(
        @NotNull UUID clientRequestId
) {
}
