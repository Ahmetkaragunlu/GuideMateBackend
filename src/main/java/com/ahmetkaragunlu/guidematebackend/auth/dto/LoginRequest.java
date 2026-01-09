package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        String email,

        @NotBlank(message = "{validation.password.notBlank}")
        String password
) {}