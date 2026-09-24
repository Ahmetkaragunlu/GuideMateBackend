package com.ahmetkaragunlu.guidematebackend.auth.dto.request;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @NotBlank(message = "{validation.token.notBlank}")
        @Size(max = 128, message = "{validation.token.size}")
        String token
) {}
