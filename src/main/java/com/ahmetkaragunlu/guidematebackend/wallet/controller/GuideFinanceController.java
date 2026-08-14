package com.ahmetkaragunlu.guidematebackend.wallet.controller;

import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Withdrawal;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.AddBankAccountRequest;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.BankAccountResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.GuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.MonthlyGuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WithdrawalRequest;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WithdrawalResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.mapper.WalletMapper;
import com.ahmetkaragunlu.guidematebackend.wallet.service.BankAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WithdrawalService;
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
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@Validated
@Tag(name = "Guide Finance")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@PreAuthorize("hasRole('GUIDE')")
@RestController
@RequestMapping("/api/v1/guide")
@RequiredArgsConstructor
public class GuideFinanceController {

    private final GuideEarningService guideEarningService;
    private final BankAccountService bankAccountService;
    private final WithdrawalService withdrawalService;
    private final WalletMapper walletMapper;

    @Operation(summary = "List guide earnings for a year")
    @GetMapping("/earnings")
    public ResponseEntity<PageResponse<GuideEarningResponse>> getEarnings(
            @RequestParam @Min(1970) @Max(9998) int year,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(PageResponse.from(
                guideEarningService.getYear(currentUser.getId(), year, page, size)
                        .map(walletMapper::toEarning)
        ));
    }

    @Operation(summary = "List monthly guide earnings for a year")
    @GetMapping("/earnings/monthly")
    public ResponseEntity<List<MonthlyGuideEarningResponse>> getMonthlyEarnings(
            @RequestParam @Min(1970) @Max(9998) int year,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(guideEarningService.getMonthlyEarnings(currentUser.getId(), year));
    }

    @Operation(summary = "List active guide bank accounts")
    @GetMapping("/bank-accounts")
    public ResponseEntity<PageResponse<BankAccountResponse>> getBankAccounts(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(PageResponse.from(
                bankAccountService.getActiveAccounts(currentUser, page, size)
                        .map(walletMapper::toBankAccount)
        ));
    }

    @Operation(summary = "Add and validate a guide bank account")
    @PostMapping("/bank-accounts")
    public ResponseEntity<BankAccountResponse> addBankAccount(
            @Valid @RequestBody AddBankAccountRequest request,
            @AuthenticationPrincipal User currentUser
    ) {
        BankAccount account = bankAccountService.add(
                currentUser,
                request.iban(),
                request.accountHolderName()
        );
        return ResponseEntity.ok(walletMapper.toBankAccount(account));
    }

    @Operation(summary = "Set the default guide bank account")
    @PostMapping("/bank-accounts/{bankAccountId}/default")
    public ResponseEntity<BankAccountResponse> makeDefault(
            @PathVariable UUID bankAccountId,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(walletMapper.toBankAccount(
                bankAccountService.makeDefault(currentUser, bankAccountId)
        ));
    }

    @Operation(summary = "Disable a guide bank account")
    @DeleteMapping("/bank-accounts/{bankAccountId}")
    public ResponseEntity<Void> deleteBankAccount(
            @PathVariable UUID bankAccountId,
            @AuthenticationPrincipal User currentUser
    ) {
        bankAccountService.delete(currentUser, bankAccountId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "List guide withdrawal history")
    @GetMapping("/withdrawals")
    public ResponseEntity<PageResponse<WithdrawalResponse>> getWithdrawals(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(50) int size,
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(PageResponse.from(
                withdrawalService.getHistory(currentUser, page, size)
                        .map(walletMapper::toWithdrawal)
        ));
    }

    @Operation(summary = "Request a simulated guide withdrawal")
    @PostMapping("/withdrawals")
    public ResponseEntity<WithdrawalResponse> requestWithdrawal(
            @Valid @RequestBody WithdrawalRequest request,
            @RequestHeader("Idempotency-Key")
            @NotBlank(message = "{validation.idempotency.notBlank}")
            @Size(max = 128, message = "{validation.idempotency.size}")
            String idempotencyKey,
            @AuthenticationPrincipal User currentUser
    ) {
        Withdrawal withdrawal = withdrawalService.request(
                currentUser,
                request.bankAccountId(),
                request.amountMinor(),
                idempotencyKey
        );
        return ResponseEntity.ok(walletMapper.toWithdrawal(withdrawal));
    }
}
