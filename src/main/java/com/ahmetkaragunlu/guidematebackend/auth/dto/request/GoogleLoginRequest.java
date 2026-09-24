package com.ahmetkaragunlu.guidematebackend.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record GoogleLoginRequest(
        @NotBlank(message = "{validation.googleToken.notBlank}")
        @Size(max = 8192, message = "{validation.googleToken.size}")
        String idToken
) {}
