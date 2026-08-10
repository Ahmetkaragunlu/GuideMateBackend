package com.ahmetkaragunlu.guidematebackend.payment.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.payment.dto.SavedPaymentMethodResponse;
import com.ahmetkaragunlu.guidematebackend.payment.service.SavedPaymentMethodService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@Tag(name = "Saved Payment Methods")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('TOURIST')")
@RestController
@RequestMapping("/api/v1/payment-methods/cards")
@RequiredArgsConstructor
public class SavedPaymentMethodController {

    private final SavedPaymentMethodService savedPaymentMethodService;

    @Operation(summary = "List provider-backed saved cards")
    @GetMapping
    public ResponseEntity<List<SavedPaymentMethodResponse>> getCards(
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(savedPaymentMethodService.getCards(currentUser));
    }

    @Operation(summary = "Delete a provider-backed saved card")
    @DeleteMapping("/{savedPaymentMethodId}")
    public ResponseEntity<Void> deleteCard(
            @PathVariable UUID savedPaymentMethodId,
            @AuthenticationPrincipal User currentUser
    ) {
        savedPaymentMethodService.deleteCard(currentUser, savedPaymentMethodId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Set the default saved card")
    @PutMapping("/{savedPaymentMethodId}/default")
    public ResponseEntity<SavedPaymentMethodResponse> makeDefault(
            @PathVariable UUID savedPaymentMethodId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(savedPaymentMethodService.makeDefault(currentUser, savedPaymentMethodId));
    }
}
