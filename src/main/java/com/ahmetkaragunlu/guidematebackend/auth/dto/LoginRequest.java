package com.ahmetkaragunlu.guidematebackend.auth.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        @Size(max = 320, message = "{validation.email.size}")
        String email,
        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 8, max = 64, message = "{validation.password.size}")
        String password
) {}
