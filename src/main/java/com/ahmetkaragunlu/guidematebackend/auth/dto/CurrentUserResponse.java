package com.ahmetkaragunlu.guidematebackend.auth.dto;

public record CurrentUserResponse(
        Long userId,
        String email,
        String firstName,
        String lastName,
        boolean roleSelected,
        String role
) {
}
