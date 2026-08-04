package com.ahmetkaragunlu.guidematebackend.tour.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.CancelTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.CreateTourRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.CreateTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.GuideTourTab;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.SubmitTourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.UpdateTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideTourCardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourReviewSubmissionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSessionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.service.GuideTourService;
import com.ahmetkaragunlu.guidematebackend.tour.service.TourSessionService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Validated
@Tag(name = "Guide Tours")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('GUIDE')")
@RestController
@RequestMapping("/api/v1/guide")
@RequiredArgsConstructor
public class GuideTourController {

    private final GuideTourService guideTourService;
    private final TourSessionService tourSessionService;

    @Operation(summary = "Submit a new tour and its first session for review")
    @PostMapping("/tours")
    public ResponseEntity<TourReviewSubmissionResponse> createTour(
            @Valid @RequestBody CreateTourRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(guideTourService.createTour(currentUser, request));
    }

    @Operation(summary = "List authenticated guide tour cards")
    @GetMapping("/tours")
    public ResponseEntity<PageResponse<GuideTourCardResponse>> getTours(
            @RequestParam(defaultValue = "ACTIVE") GuideTourTab tab,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideTourService.getGuideTours(currentUser, tab, page, size));
    }

    @Operation(summary = "Get an authenticated guide-owned tour")
    @GetMapping("/tours/{tourId}")
    public ResponseEntity<TourDetailResponse> getTour(
            @PathVariable UUID tourId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideTourService.getOwnedTour(currentUser, tourId));
    }

    @Operation(summary = "Resubmit a rejected tour or submit an approved-tour change request")
    @PostMapping("/tours/{tourId}/change-requests")
    public ResponseEntity<TourReviewSubmissionResponse> submitChange(
            @PathVariable UUID tourId,
            @Valid @RequestBody SubmitTourChangeRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(guideTourService.submitChange(currentUser, tourId, request));
    }

    @Operation(summary = "Create a new session under an approved tour")
    @PostMapping("/tours/{tourId}/sessions")
    public ResponseEntity<TourSessionResponse> addSession(
            @PathVariable UUID tourId,
            @Valid @RequestBody CreateTourSessionRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(tourSessionService.addSession(currentUser, tourId, request));
    }

    @Operation(summary = "Update a future manageable session")
    @PatchMapping("/sessions/{sessionId}")
    public ResponseEntity<TourSessionResponse> updateSession(
            @PathVariable UUID sessionId,
            @Valid @RequestBody UpdateTourSessionRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(tourSessionService.updateSession(currentUser, sessionId, request));
    }

    @Operation(summary = "Open a future approved session for booking")
    @PostMapping("/sessions/{sessionId}/open")
    public ResponseEntity<TourSessionResponse> openSession(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(tourSessionService.openSession(currentUser, sessionId));
    }

    @Operation(summary = "Close a future session to new bookings")
    @PostMapping("/sessions/{sessionId}/close")
    public ResponseEntity<TourSessionResponse> closeSession(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(tourSessionService.closeSession(currentUser, sessionId));
    }

    @Operation(summary = "Cancel a future session as its guide")
    @PostMapping("/sessions/{sessionId}/cancel")
    public ResponseEntity<TourSessionResponse> cancelSession(
            @PathVariable UUID sessionId,
            @RequestHeader("Idempotency-Key")
            @NotBlank(message = "{validation.idempotency.notBlank}")
            @Size(max = 128, message = "{validation.idempotency.size}")
            String idempotencyKey,
            @Valid @RequestBody CancelTourSessionRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(tourSessionService.cancelSession(
                currentUser,
                sessionId,
                idempotencyKey,
                request
        ));
    }

    @Operation(summary = "Archive an unpublished rejected tour")
    @PostMapping("/tours/{tourId}/archive")
    public ResponseEntity<TourDetailResponse> archiveTour(
            @PathVariable UUID tourId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideTourService.archiveTour(currentUser, tourId));
    }
}
