package com.ahmetkaragunlu.guidematebackend.auth.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.response.MediaReferenceResponse;

public record CurrentUserResponse(
        Long userId,
        String email,
        String firstName,
        String lastName,
        boolean roleSelected,
        String role,
        MediaReferenceResponse avatar
) {
}
