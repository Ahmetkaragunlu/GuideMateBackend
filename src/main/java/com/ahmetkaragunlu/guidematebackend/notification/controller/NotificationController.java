package com.ahmetkaragunlu.guidematebackend.notification.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.dto.UnreadCountResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationPreferenceResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.UpdateNotificationPreferenceRequest;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPreferenceService;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Validated
@Tag(name = "Notifications")
@RestController
@RequestMapping("/api/v1/notifications")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;
    private final NotificationPreferenceService preferenceService;

    @Operation(summary = "List the current user's durable notifications")
    @GetMapping
    public ResponseEntity<PageResponse<NotificationResponse>> getNotifications(
            @AuthenticationPrincipal User currentUser,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size
    ) {
        return ResponseEntity.ok(notificationService.getNotifications(currentUser, page, size));
    }

    @Operation(summary = "Get the current user's notification unread count")
    @GetMapping("/unread-count")
    public ResponseEntity<UnreadCountResponse> unreadCount(@AuthenticationPrincipal User currentUser) {
        return ResponseEntity.ok(notificationService.unreadCount(currentUser));
    }

    @Operation(summary = "Mark one owned notification as read")
    @PostMapping("/{notificationId}/read")
    public ResponseEntity<NotificationResponse> markRead(
            @AuthenticationPrincipal User currentUser,
            @PathVariable UUID notificationId
    ) {
        return ResponseEntity.ok(notificationService.markRead(currentUser, notificationId));
    }

    @Operation(summary = "Mark all current user's notifications as read")
    @PostMapping("/read-all")
    public ResponseEntity<UnreadCountResponse> markAllRead(@AuthenticationPrincipal User currentUser) {
        return ResponseEntity.ok(notificationService.markAllRead(currentUser));
    }

    @Operation(summary = "Get the current user's push notification preferences")
    @GetMapping("/preferences")
    public ResponseEntity<NotificationPreferenceResponse> getPreferences(
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(preferenceService.get(currentUser));
    }

    @Operation(summary = "Partially update the current user's push notification preferences")
    @PatchMapping("/preferences")
    public ResponseEntity<NotificationPreferenceResponse> updatePreferences(
            @AuthenticationPrincipal User currentUser,
            @RequestBody UpdateNotificationPreferenceRequest request
    ) {
        return ResponseEntity.ok(preferenceService.update(currentUser, request));
    }
}
