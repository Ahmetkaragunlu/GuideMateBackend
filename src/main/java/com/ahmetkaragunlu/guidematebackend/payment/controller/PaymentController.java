package com.ahmetkaragunlu.guidematebackend.payment.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.dto.PaymentResponse;
import com.ahmetkaragunlu.guidematebackend.payment.dto.CheckoutCurrenciesResponse;
import com.ahmetkaragunlu.guidematebackend.payment.dto.PaymentQuoteResponse;
import com.ahmetkaragunlu.guidematebackend.payment.dto.TourPaymentQuoteRequest;
import com.ahmetkaragunlu.guidematebackend.payment.dto.TourCheckoutRequest;
import com.ahmetkaragunlu.guidematebackend.payment.dto.WalletTopUpRequest;
import com.ahmetkaragunlu.guidematebackend.payment.dto.WalletTopUpQuoteRequest;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentCheckoutService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentQueryService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentQuoteService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Validated
@Tag(name = "Payments")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('TOURIST')")
@RestController
@RequestMapping("/api/v1/payments")
@RequiredArgsConstructor
public class PaymentController {

    private final PaymentCheckoutService checkoutService;
    private final PaymentIntentService paymentIntentService;
    private final PaymentQueryService paymentQueryService;
    private final PaymentQuoteService paymentQuoteService;

    @Operation(summary = "List enabled hosted checkout currencies")
    @GetMapping("/checkout/currencies")
    public ResponseEntity<CheckoutCurrenciesResponse> getCheckoutCurrencies() {
        return ResponseEntity.ok(paymentQuoteService.getCurrencyOptions());
    }

    @Operation(summary = "Quote a hosted card charge for a tour purchase")
    @PostMapping("/checkout/tour/quote")
    public ResponseEntity<PaymentQuoteResponse> quoteTour(
            @Valid @RequestBody TourPaymentQuoteRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(paymentQuoteService.quoteTour(
                currentUser,
                request.sessionId(),
                request.participantCount(),
                request.chargeCurrencyCode()
        ));
    }

    @Operation(summary = "Quote a hosted card charge for a wallet top-up")
    @PostMapping("/checkout/wallet-top-up/quote")
    public ResponseEntity<PaymentQuoteResponse> quoteWalletTopUp(
            @Valid @RequestBody WalletTopUpQuoteRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(paymentQuoteService.quoteWalletTopUp(
                currentUser,
                request.amountMinor(),
                request.chargeCurrencyCode()
        ));
    }

    @Operation(summary = "Purchase a tour with hosted card checkout or wallet balance")
    @PostMapping("/checkout/tour")
    public ResponseEntity<PaymentResponse> checkoutTour(
            @Valid @RequestBody TourCheckoutRequest request,
            @RequestHeader("Idempotency-Key")
            @NotBlank(message = "{validation.idempotency.notBlank}")
            @Size(max = 128, message = "{validation.idempotency.size}")
            String idempotencyKey,
            @AuthenticationPrincipal User currentUser
    ) {
        Payment payment = checkoutService.checkoutTour(
                currentUser,
                request.sessionId(),
                request.participantCount(),
                request.method(),
                request.quoteId(),
                request.locale(),
                idempotencyKey
        );
        return ResponseEntity.ok(paymentQueryService.getOwned(currentUser, payment));
    }

    @Operation(summary = "Initialize an iyzico hosted checkout for wallet top-up")
    @PostMapping("/checkout/wallet-top-up")
    public ResponseEntity<PaymentResponse> checkoutWalletTopUp(
            @Valid @RequestBody WalletTopUpRequest request,
            @RequestHeader("Idempotency-Key")
            @NotBlank(message = "{validation.idempotency.notBlank}")
            @Size(max = 128, message = "{validation.idempotency.size}")
            String idempotencyKey,
            @AuthenticationPrincipal User currentUser
    ) {
        Payment payment = checkoutService.checkoutWalletTopUp(
                currentUser,
                request.quoteId(),
                request.locale(),
                idempotencyKey
        );
        return ResponseEntity.ok(paymentQueryService.getOwned(currentUser, payment));
    }

    @Operation(summary = "Get canonical payment, reservation and refund state")
    @GetMapping("/{paymentId}")
    public ResponseEntity<PaymentResponse> getPayment(
            @PathVariable UUID paymentId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(paymentQueryService.getOwned(currentUser, paymentId));
    }

    @Operation(summary = "Cancel a pending hosted payment")
    @PostMapping("/{paymentId}/cancel")
    public ResponseEntity<PaymentResponse> cancelPayment(
            @PathVariable UUID paymentId,
            @AuthenticationPrincipal User currentUser
    ) {
        Payment payment = paymentIntentService.cancel(currentUser, paymentId);
        return ResponseEntity.ok(paymentQueryService.getOwned(currentUser, payment));
    }
}
