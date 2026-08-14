package com.ahmetkaragunlu.guidematebackend.wallet.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WalletResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WalletTransactionResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletBalance;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletTransactionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Validated
@Tag(name = "Wallet")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasAnyRole('TOURIST', 'GUIDE')")
@RestController
@RequestMapping("/api/v1/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletAccountService walletAccountService;
    private final WalletTransactionQueryService walletTransactionQueryService;

    @Operation(summary = "Get canonical wallet and withdrawable balances")
    @GetMapping
    public ResponseEntity<WalletResponse> getWallet(@AuthenticationPrincipal User currentUser) {
        WalletBalance balance = walletAccountService.getBalance(currentUser);
        return ResponseEntity.ok(new WalletResponse(
                balance.balanceMinor(),
                balance.availableBalanceMinor(),
                balance.currencyCode()
        ));
    }

    @Operation(summary = "List wallet ledger transactions")
    @GetMapping("/transactions")
    public ResponseEntity<PageResponse<WalletTransactionResponse>> getTransactions(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(walletTransactionQueryService.getTransactions(
                currentUser,
                page,
                size
        ));
    }
}
