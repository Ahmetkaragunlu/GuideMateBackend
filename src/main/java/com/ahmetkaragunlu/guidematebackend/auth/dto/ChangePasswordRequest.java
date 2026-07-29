package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record ChangePasswordRequest(
        @NotBlank(message = "{validation.password.notBlank}")
        String currentPassword,

        @NotBlank(message = "{validation.password.notBlank}")
        String newPassword
) {
}
