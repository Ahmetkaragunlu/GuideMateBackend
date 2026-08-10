package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerDirection;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WalletLedgerEntry;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WithdrawalStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletLedgerRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WithdrawalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class WalletAccountService {

    private static final List<WithdrawalStatus> RESERVED_WITHDRAWAL_STATUSES = List.of(
            WithdrawalStatus.PENDING,
            WithdrawalStatus.PROCESSING
    );

    private final WalletRepository walletRepository;
    private final WalletLedgerRepository ledgerRepository;
    private final WithdrawalRepository withdrawalRepository;
    private final PaymentProperties paymentProperties;

    @Transactional
    public Wallet getOrCreateForUpdate(User user) {
        return walletRepository.findByUserIdForUpdate(user.getId())
                .orElseGet(() -> walletRepository.saveAndFlush(
                        new Wallet(user, paymentProperties.currencyCode())
                ));
    }

    @Transactional(readOnly = true)
    public WalletBalance getBalance(User user) {
        Wallet wallet = walletRepository.findByUser_Id(user.getId()).orElse(null);
        if (wallet == null) {
            return new WalletBalance(0, 0, paymentProperties.currencyCode());
        }
        return balance(wallet);
    }

    @Transactional(readOnly = true)
    public Page<WalletLedgerEntry> getTransactions(User user, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        Wallet wallet = walletRepository.findByUser_Id(user.getId()).orElse(null);
        if (wallet == null) {
            return Page.empty(pageRequest);
        }
        return ledgerRepository.findByWallet_IdOrderByOccurredAtDesc(wallet.getId(), pageRequest);
    }

    public WalletBalance balance(Wallet wallet) {
        long balanceMinor = ledgerRepository.balance(wallet.getId(), LedgerDirection.CREDIT);
        long reservedMinor = withdrawalRepository.reservedAmount(
                wallet.getId(),
                RESERVED_WITHDRAWAL_STATUSES
        );
        return new WalletBalance(
                balanceMinor,
                Math.max(0, balanceMinor - reservedMinor),
                wallet.getCurrencyCode()
        );
    }

    public void credit(
            Wallet wallet,
            long amountMinor,
            LedgerEntryType type,
            String referenceType,
            UUID referenceId,
            String idempotencyKey,
            Instant occurredAt
    ) {
        addEntry(
                wallet,
                LedgerDirection.CREDIT,
                amountMinor,
                type,
                referenceType,
                referenceId,
                idempotencyKey,
                occurredAt
        );
    }

    public void debit(
            Wallet wallet,
            long amountMinor,
            LedgerEntryType type,
            String referenceType,
            UUID referenceId,
            String idempotencyKey,
            Instant occurredAt
    ) {
        if (ledgerRepository.findByWallet_IdAndIdempotencyKey(wallet.getId(), idempotencyKey).isPresent()) {
            return;
        }
        if (balance(wallet).availableBalanceMinor() < amountMinor) {
            throw new BusinessException(ErrorCode.INSUFFICIENT_WALLET_BALANCE);
        }
        addEntry(
                wallet,
                LedgerDirection.DEBIT,
                amountMinor,
                type,
                referenceType,
                referenceId,
                idempotencyKey,
                occurredAt
        );
    }

    public void recordMandatoryDebit(
            Wallet wallet,
            long amountMinor,
            LedgerEntryType type,
            String referenceType,
            UUID referenceId,
            String idempotencyKey,
            Instant occurredAt
    ) {
        addEntry(
                wallet,
                LedgerDirection.DEBIT,
                amountMinor,
                type,
                referenceType,
                referenceId,
                idempotencyKey,
                occurredAt
        );
    }

    private void addEntry(
            Wallet wallet,
            LedgerDirection direction,
            long amountMinor,
            LedgerEntryType type,
            String referenceType,
            UUID referenceId,
            String idempotencyKey,
            Instant occurredAt
    ) {
        if (amountMinor <= 0) {
            throw new BusinessException(ErrorCode.INVALID_AMOUNT);
        }
        if (ledgerRepository.findByWallet_IdAndIdempotencyKey(wallet.getId(), idempotencyKey).isPresent()) {
            return;
        }
        ledgerRepository.save(new WalletLedgerEntry(
                wallet,
                direction,
                type,
                amountMinor,
                referenceType,
                referenceId,
                idempotencyKey,
                occurredAt
        ));
    }
}
