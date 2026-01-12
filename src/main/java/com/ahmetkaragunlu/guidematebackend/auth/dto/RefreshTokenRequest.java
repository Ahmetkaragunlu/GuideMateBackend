package com.ahmetkaragunlu.guidematebackend.auth.dto;


import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
        @NotBlank(message = "{validation.token.notBlank}")
        String token
) {}