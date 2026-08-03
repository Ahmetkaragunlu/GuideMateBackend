package com.ahmetkaragunlu.guidematebackend.profile.controller;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.profile.service.GuideDiscoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Validated
@Tag(name = "Guide Discovery")
@RestController
@RequestMapping("/api/v1/guides")
@RequiredArgsConstructor
public class GuideDiscoveryController {

    private final GuideDiscoveryService guideDiscoveryService;

    @Operation(summary = "Search active public guide profiles")
    @GetMapping("/search")
    public ResponseEntity<PageResponse<GuideSearchItemResponse>> search(
            @RequestParam(required = false) @Size(max = 100) String q,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size
    ) {
        return ResponseEntity.ok(guideDiscoveryService.search(q, page, size));
    }

    @Operation(summary = "List top active guides")
    @GetMapping("/top")
    public ResponseEntity<List<GuideSearchItemResponse>> top(
            @RequestParam(defaultValue = "10") @Min(1) @Max(20) int limit
    ) {
        return ResponseEntity.ok(guideDiscoveryService.top(limit));
    }
}
