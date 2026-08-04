package com.ahmetkaragunlu.guidematebackend.reservation.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationTripStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.CancelReservationRequest;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationCancellationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationService;
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
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Validated
@Tag(name = "Reservations")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('TOURIST')")
@RestController
@RequestMapping("/api/v1/reservations")
@RequiredArgsConstructor
public class ReservationController {

    private final ReservationService reservationService;

    @Operation(summary = "List authenticated tourist trips")
    @GetMapping("/me")
    public ResponseEntity<PageResponse<ReservationResponse>> getMyTrips(
            @RequestParam(defaultValue = "UPCOMING") ReservationTripStatus status,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(reservationService.getMyTrips(currentUser, status, page, size));
    }

    @Operation(summary = "Get an authenticated tourist-owned reservation")
    @GetMapping("/{reservationId}")
    public ResponseEntity<ReservationResponse> getReservation(
            @PathVariable UUID reservationId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(reservationService.getOwnedReservation(currentUser, reservationId));
    }

    @Operation(summary = "Cancel an authenticated tourist-owned reservation")
    @PostMapping("/{reservationId}/cancel")
    public ResponseEntity<ReservationCancellationResponse> cancel(
            @PathVariable UUID reservationId,
            @RequestHeader("Idempotency-Key")
            @NotBlank(message = "{validation.idempotency.notBlank}")
            @Size(max = 128, message = "{validation.idempotency.size}")
            String idempotencyKey,
            @Valid @RequestBody CancelReservationRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(reservationService.cancel(
                currentUser,
                reservationId,
                idempotencyKey,
                request
        ));
    }
}
