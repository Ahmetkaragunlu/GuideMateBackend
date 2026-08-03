package com.ahmetkaragunlu.guidematebackend.profile.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideProfileResponse;
import com.ahmetkaragunlu.guidematebackend.profile.dto.UpdateGuideProfileRequest;
import com.ahmetkaragunlu.guidematebackend.profile.service.GuideProfileService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Guide Profiles")
@RestController
@RequestMapping("/api/v1/guides")
@RequiredArgsConstructor
public class GuideProfileController {

    private final GuideProfileService guideProfileService;

    @Operation(summary = "Get the authenticated guide profile")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
    @PreAuthorize("hasRole('GUIDE')")
    @GetMapping("/me/profile")
    public ResponseEntity<GuideProfileResponse> ownProfile(
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideProfileService.getOwnProfile(currentUser));
    }

    @Operation(summary = "Update the authenticated guide profile")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
    @PreAuthorize("hasRole('GUIDE')")
    @PatchMapping("/me/profile")
    public ResponseEntity<GuideProfileResponse> updateProfile(
            @Valid @RequestBody UpdateGuideProfileRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideProfileService.updateProfile(currentUser, request));
    }

    @Operation(summary = "Get a public guide profile")
    @GetMapping("/{guideId}/public-profile")
    public ResponseEntity<GuideProfileResponse> publicProfile(@PathVariable Long guideId) {
        return ResponseEntity.ok(guideProfileService.getPublicProfile(guideId));
    }
}
