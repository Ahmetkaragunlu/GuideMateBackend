package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RegisterRequest(
        @NotBlank(message = "{validation.firstName.notBlank}")
        @Pattern(
                regexp = "^ *(?=(?:\\P{L}*\\p{L}){3,}\\P{L}*$)\\p{L}+(?:[ '\\u2019-]\\p{L}+)* *$",
                message = "{validation.firstName.format}"
        )
        String firstName,

        @NotBlank(message = "{validation.lastName.notBlank}")
        @Pattern(
                regexp = "^ *(?=(?:\\P{L}*\\p{L}){2,}\\P{L}*$)\\p{L}+(?:[ '\\u2019-]\\p{L}+)* *$",
                message = "{validation.lastName.format}"
        )
        String lastName,

        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        String email,

        @NotBlank(message = "{validation.password.notBlank}")
        String password
) {
}
