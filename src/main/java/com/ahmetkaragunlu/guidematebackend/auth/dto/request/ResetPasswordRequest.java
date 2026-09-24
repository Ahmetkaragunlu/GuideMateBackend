package com.ahmetkaragunlu.guidematebackend.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank(message = "{validation.token.notBlank}")
        @Size(max = 128, message = "{validation.token.size}")
        String token,

        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 8, max = 64, message = "{validation.password.size}")
        String newPassword,

        @NotBlank(message = "{validation.field.required}")
        @Size(min = 8, max = 64, message = "{validation.password.size}")
        String confirmPassword
) {
}
