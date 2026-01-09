package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "{validation.firstName.notBlank}")
        @Size(min = 3, message = "{validation.firstName.size}")
        String firstName,

        @NotBlank(message = "{validation.lastName.notBlank}")
        @Size(min = 2, message = "{validation.lastName.size}")
        String lastName,

        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        String email,

        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 6, message = "{validation.password.size}")
        String password
) {}