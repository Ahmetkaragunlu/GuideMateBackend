package com.ahmetkaragunlu.guidematebackend.tour.controller;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourSearchSort;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.tour.service.TourDiscoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
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
            @RequestParam(required = false) @Size(max = 100) String q,
            @RequestParam(required = false) String countryCode,
            @RequestParam(required = false) @Size(max = 255) String cityPlaceId,
            @RequestParam(required = false) String categoryCode,
            @RequestParam(required = false) List<String> languageCodes,
            @RequestParam(required = false) @DecimalMin("0.0") @DecimalMax("5.0") Double minRating,
            @RequestParam(required = false) @PositiveOrZero Long minPriceMinor,
            @RequestParam(required = false) @PositiveOrZero Long maxPriceMinor,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @RequestParam(defaultValue = "STARTS_AT_ASC") TourSearchSort sort
    ) {
        return ResponseEntity.ok(tourDiscoveryService.search(
                q,
                countryCode,
                cityPlaceId,
                categoryCode,
                languageCodes,
                minRating,
                minPriceMinor,
                maxPriceMinor,
                page,
                size,
                sort
        ));
    }

    @Operation(summary = "List popular bookable tour sessions")
    @GetMapping("/popular")
    public ResponseEntity<PageResponse<TourSearchItemResponse>> popular(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(20) int size
    ) {
        return ResponseEntity.ok(tourDiscoveryService.popular(page, size));
    }

    @Operation(summary = "Get an approved tour with its nearest future session")
    @GetMapping("/{tourId}")
    public ResponseEntity<TourDetailResponse> getTour(@PathVariable UUID tourId) {
        return ResponseEntity.ok(tourDiscoveryService.getTour(tourId));
    }
}
