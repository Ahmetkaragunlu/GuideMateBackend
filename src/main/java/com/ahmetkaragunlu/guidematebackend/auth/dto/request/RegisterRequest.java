package com.ahmetkaragunlu.guidematebackend.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "{validation.firstName.notBlank}")
        @Size(max = 100, message = "{validation.firstName.size}")
        @Pattern(
                regexp = "^ *(?=(?:\\P{L}*\\p{L}){3,}\\P{L}*$)\\p{L}+(?:[ '\\u2019-]\\p{L}+)* *$",
                message = "{validation.firstName.format}"
        )
        String firstName,

        @NotBlank(message = "{validation.lastName.notBlank}")
        @Size(max = 100, message = "{validation.lastName.size}")
        @Pattern(
                regexp = "^ *(?=(?:\\P{L}*\\p{L}){2,}\\P{L}*$)\\p{L}+(?:[ '\\u2019-]\\p{L}+)* *$",
                message = "{validation.lastName.format}"
        )
        String lastName,

        @NotBlank(message = "{validation.email.notBlank}")
        @Email(message = "{validation.email.invalid}")
        @Size(max = 320, message = "{validation.email.size}")
        String email,

        @NotBlank(message = "{validation.password.notBlank}")
        @Size(min = 8, max = 64, message = "{validation.password.size}")
        String password
) {
}
