package com.ahmetkaragunlu.guidematebackend.tour.controller;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourSearchRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.tour.service.TourDiscoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Positive;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Validated
@Tag(name = "Tour Discovery")
@RestController
@RequestMapping("/api/v1/tours")
@RequiredArgsConstructor
public class TourDiscoveryController {

    private final TourDiscoveryService tourDiscoveryService;

    @Operation(summary = "Search bookable tour sessions")
    @GetMapping("/search")
    public ResponseEntity<PageResponse<TourSearchItemResponse>> search(
            @Valid @ParameterObject @ModelAttribute TourSearchRequest request
    ) {
        return ResponseEntity.ok(tourDiscoveryService.search(request));
    }

    @Operation(summary = "List popular bookable tour sessions")
    @GetMapping("/popular")
    public ResponseEntity<PageResponse<TourSearchItemResponse>> popular(
            @RequestParam(required = false) @Positive Long guideId,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(20) int size
    ) {
        return ResponseEntity.ok(tourDiscoveryService.popular(guideId, page, size));
    }

    @Operation(summary = "Get an approved tour with its nearest future session")
    @GetMapping("/{tourId}")
    public ResponseEntity<TourDetailResponse> getTour(@PathVariable UUID tourId) {
        return ResponseEntity.ok(tourDiscoveryService.getTour(tourId));
    }
}
