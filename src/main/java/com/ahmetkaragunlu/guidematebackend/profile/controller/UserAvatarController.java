package com.ahmetkaragunlu.guidematebackend.profile.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.profile.dto.UpdateUserAvatarRequest;
import com.ahmetkaragunlu.guidematebackend.profile.service.UserAvatarService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "User Profile")
@RestController
@RequestMapping("/api/v1/users/me/avatar")
@RequiredArgsConstructor
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class UserAvatarController {

    private final UserAvatarService userAvatarService;

    @Operation(summary = "Replace the current user's avatar")
    @PreAuthorize("hasAnyRole('TOURIST', 'GUIDE')")
    @PutMapping
    public ResponseEntity<MediaReferenceResponse> update(
            @Valid @RequestBody UpdateUserAvatarRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(userAvatarService.update(currentUser.getId(), request.avatarMediaId()));
    }
}
