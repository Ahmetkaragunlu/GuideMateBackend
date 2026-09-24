package com.ahmetkaragunlu.guidematebackend.auth.mapper;

import com.ahmetkaragunlu.guidematebackend.auth.dto.response.AuthResponse;
import com.ahmetkaragunlu.guidematebackend.auth.dto.response.CurrentUserResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthResponseMapper {

    private final MediaReferenceMapper mediaReferenceMapper;

    public AuthResponse toAuthResponse(
            User user,
            String accessToken,
            String refreshToken,
            String message
    ) {
        return new AuthResponse(
                accessToken,
                refreshToken,
                message,
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isRoleSelected(),
                roleName(user),
                mediaReferenceMapper.fromId(user.getAvatarMediaId())
        );
    }

    public CurrentUserResponse toCurrentUserResponse(User user) {
        return new CurrentUserResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isRoleSelected(),
                roleName(user),
                mediaReferenceMapper.fromId(user.getAvatarMediaId())
        );
    }

    private String roleName(User user) {
        return user.getRole() == null ? null : user.getRole().getName();
    }
}
