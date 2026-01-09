package com.ahmetkaragunlu.guidematebackend.auth.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record LoginRequest(
        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        String email,

        @NotBlank(message = "{validation.password.notBlank}")
        @Pattern(regexp = "^\\d{6}$", message = "{validation.password.numeric}")
        String password
) {}