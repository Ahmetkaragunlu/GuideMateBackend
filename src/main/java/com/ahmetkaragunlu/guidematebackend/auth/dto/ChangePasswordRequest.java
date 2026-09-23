package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 8, max = 64, message = "{validation.password.size}")
        String currentPassword,

        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 8, max = 64, message = "{validation.password.size}")
        String newPassword
) {
}
