package com.ahmetkaragunlu.guidematebackend.auth.dto;

public record AuthResponse(
        String token,
        String message,
        boolean roleSelected,
        String role
) {}