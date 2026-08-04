package com.ahmetkaragunlu.guidematebackend.review.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.review.dto.CreateReviewRequest;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.dto.TourReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
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
@Tag(name = "Reviews")
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class ReviewController {

    private final ReviewService reviewService;
    private final ReviewQueryService reviewQueryService;

    @Operation(summary = "Submit one review for a completed owned reservation")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
    @PreAuthorize("hasRole('TOURIST')")
    @PostMapping("/reservations/{reservationId}/reviews")
    public ResponseEntity<ReviewResponse> submit(
            @PathVariable UUID reservationId,
            @Valid @RequestBody CreateReviewRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(reviewService.submit(currentUser, reservationId, request));
    }

    @Operation(summary = "List public reviews for an approved tour")
    @GetMapping("/tours/{tourId}/reviews")
    public ResponseEntity<PageResponse<TourReviewResponse>> getTourReviews(
            @PathVariable UUID tourId,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size
    ) {
        return ResponseEntity.ok(reviewQueryService.getTourReviews(tourId, page, size));
    }
}
