package com.ahmetkaragunlu.guidematebackend.auth.dto;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String message,
        Long userId,
        String email,
        String firstName,
        String lastName,
        boolean roleSelected,
        String role,
        MediaReferenceResponse avatar
) {
}
