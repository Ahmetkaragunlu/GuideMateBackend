package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record ResetPasswordRequest(
        @NotBlank(message = "{validation.token.notBlank}")
        String token,

        @NotBlank(message = "{validation.password.notBlank}")
        String newPassword,

        @NotBlank(message = "{validation.field.required}")
        String confirmPassword
) {
}
