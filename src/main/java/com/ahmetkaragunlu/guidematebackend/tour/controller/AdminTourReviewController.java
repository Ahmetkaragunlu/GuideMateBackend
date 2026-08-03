package com.ahmetkaragunlu.guidematebackend.tour.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.RejectTourReviewRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewDecisionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewSummaryResponse;
import com.ahmetkaragunlu.guidematebackend.tour.service.AdminTourReviewService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Validated
@Tag(name = "Admin Tour Reviews")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('ADMIN')")
@RestController
@RequestMapping("/api/v1/admin/tour-reviews")
@RequiredArgsConstructor
public class AdminTourReviewController {

    private final AdminTourReviewService adminTourReviewService;

    @Operation(summary = "List pending new-tour and tour-change reviews")
    @GetMapping
    public ResponseEntity<PageResponse<AdminTourReviewSummaryResponse>> getPendingReviews(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size
    ) {
        return ResponseEntity.ok(adminTourReviewService.getPendingReviews(page, size));
    }

    @Operation(summary = "Get a tour review with current and proposed state")
    @GetMapping("/{reviewId}")
    public ResponseEntity<AdminTourReviewDetailResponse> getReview(@PathVariable UUID reviewId) {
        return ResponseEntity.ok(adminTourReviewService.getReview(reviewId));
    }

    @Operation(summary = "Approve a pending tour review")
    @PostMapping("/{reviewId}/approve")
    public ResponseEntity<AdminTourReviewDecisionResponse> approve(
            @PathVariable UUID reviewId,
            @AuthenticationPrincipal User currentAdmin
    ) {
        return ResponseEntity.ok(adminTourReviewService.approve(currentAdmin, reviewId));
    }

    @Operation(summary = "Reject a pending tour review")
    @PostMapping("/{reviewId}/reject")
    public ResponseEntity<AdminTourReviewDecisionResponse> reject(
            @PathVariable UUID reviewId,
            @Valid @RequestBody RejectTourReviewRequest request,
            @AuthenticationPrincipal User currentAdmin
    ) {
        return ResponseEntity.ok(adminTourReviewService.reject(currentAdmin, reviewId, request.reason()));
    }
}
