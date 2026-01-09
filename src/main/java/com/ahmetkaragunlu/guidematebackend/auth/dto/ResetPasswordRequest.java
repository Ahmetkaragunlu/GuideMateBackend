package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank(message = "{validation.token.notBlank}")
        String token,

        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 6, message = "{validation.password.size}")
        String newPassword,

        @NotBlank(message = "{validation.field.required}")
        String confirmPassword
) {}