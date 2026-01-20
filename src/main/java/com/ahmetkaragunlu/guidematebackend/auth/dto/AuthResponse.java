package com.ahmetkaragunlu.guidematebackend.auth.dto;


public record AuthResponse(
        String accessToken,
        String refreshToken,
        String message,
        boolean roleSelected,
        String role,
        String firstName
) {}