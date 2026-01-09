package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        String email,

        @NotBlank(message = "{validation.firstName.notBlank}")
        String firstName,

        @NotBlank(message = "{validation.lastName.notBlank}")
        String lastName
) {}