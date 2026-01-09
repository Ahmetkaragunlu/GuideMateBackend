package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record GoogleLoginRequest(
        @NotBlank(message = "{validation.googleToken.notBlank}")
        String idToken
) {}