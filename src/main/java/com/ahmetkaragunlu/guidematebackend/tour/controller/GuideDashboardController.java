package com.ahmetkaragunlu.guidematebackend.tour.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideDashboardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.service.GuideDashboardService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Guide Dashboard")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('GUIDE')")
@RestController
@RequestMapping("/api/v1/guides/me/dashboard")
@RequiredArgsConstructor
public class GuideDashboardController {

    private final GuideDashboardService guideDashboardService;

    @Operation(summary = "Get the authenticated guide dashboard projection")
    @GetMapping
    public ResponseEntity<GuideDashboardResponse> getDashboard(
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideDashboardService.getDashboard(currentUser));
    }
}
