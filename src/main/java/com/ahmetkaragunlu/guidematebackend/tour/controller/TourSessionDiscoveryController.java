package com.ahmetkaragunlu.guidematebackend.tour.controller;

import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.service.TourDiscoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Tag(name = "Tour Discovery")
@RestController
@RequestMapping("/api/v1/tour-sessions")
@RequiredArgsConstructor
public class TourSessionDiscoveryController {

    private final TourDiscoveryService tourDiscoveryService;

    @Operation(summary = "Get an approved tour by exact session")
    @GetMapping("/{sessionId}")
    public ResponseEntity<TourDetailResponse> getSession(@PathVariable UUID sessionId) {
        return ResponseEntity.ok(tourDiscoveryService.getSession(sessionId));
    }
}
