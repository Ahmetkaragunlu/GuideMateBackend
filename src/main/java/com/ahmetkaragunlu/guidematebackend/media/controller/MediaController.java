package com.ahmetkaragunlu.guidematebackend.media.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaDeletionResponse;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaUploadResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaContent;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUploadPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.time.Duration;
import java.util.UUID;

@Tag(name = "Media")
@RestController
@RequestMapping("/api/v1/media")
@RequiredArgsConstructor
public class MediaController {

    private final MediaService mediaService;
    private final MediaUploadPolicy mediaUploadPolicy;

    @Operation(summary = "Upload an owned user avatar or guide tour cover")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
    @PreAuthorize("hasAnyRole('TOURIST', 'GUIDE')")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<MediaUploadResponse> upload(
            @RequestPart("file") MultipartFile file,
            @RequestParam("purpose") MediaPurpose purpose,
            @AuthenticationPrincipal User currentUser
    ) {
        mediaUploadPolicy.requireAllowed(currentUser, purpose);
        MediaUploadResponse response = mediaService.upload(file, purpose, currentUser.getId());
        return ResponseEntity.created(URI.create(response.imageUrl())).body(response);
    }

    @Operation(summary = "Read public or owner-accessible image content")
    @GetMapping(value = "/{mediaId}/content")
    public ResponseEntity<byte[]> content(
            @PathVariable UUID mediaId,
            @AuthenticationPrincipal User currentUser
    ) {
        Long requesterUserId = currentUser == null ? null : currentUser.getId();
        MediaContent content = mediaService.getContent(mediaId, requesterUserId);
        CacheControl cacheControl = content.publiclyAccessible()
                ? CacheControl.maxAge(Duration.ofHours(1)).cachePublic()
                : CacheControl.noStore();

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(content.contentType()))
                .contentLength(content.bytes().length)
                .cacheControl(cacheControl)
                .body(content.bytes());
    }

    @Operation(summary = "Delete an unreferenced owned image")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
    @PreAuthorize("hasAnyRole('TOURIST', 'GUIDE')")
    @DeleteMapping("/{mediaId}")
    public ResponseEntity<MediaDeletionResponse> delete(
            @PathVariable UUID mediaId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(mediaService.delete(mediaId, currentUser.getId()));
    }
}
