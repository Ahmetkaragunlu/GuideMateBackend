package com.ahmetkaragunlu.guidematebackend.notification.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.notification.dto.DeviceRegistrationResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.RegisterDeviceRegistrationRequest;
import com.ahmetkaragunlu.guidematebackend.notification.service.DeviceRegistrationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Tag(name = "Devices")
@RestController
@RequestMapping("/api/v1/devices/fcm-registration")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@RequiredArgsConstructor
public class DeviceRegistrationController {

    private final DeviceRegistrationService registrationService;

    @Operation(summary = "Register or refresh the current Android Firebase Installation ID")
    @PostMapping
    public ResponseEntity<DeviceRegistrationResponse> register(
            @AuthenticationPrincipal User currentUser,
            @Valid @RequestBody RegisterDeviceRegistrationRequest request
    ) {
        return ResponseEntity.ok(registrationService.register(currentUser, request));
    }

    @Operation(summary = "Deactivate the current user's Android Firebase registration")
    @DeleteMapping("/{installationId}")
    public ResponseEntity<Void> deactivate(
            @AuthenticationPrincipal User currentUser,
            @PathVariable UUID installationId
    ) {
        registrationService.deactivate(currentUser.getId(), installationId);
        return ResponseEntity.noContent().build();
    }
}
