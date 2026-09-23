package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.support.TestPaymentProperties;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerDirection;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WalletLedgerEntry;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletLedgerRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WithdrawalRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WalletAccountServiceTest {

    @Mock private WalletRepository walletRepository;
    @Mock private WalletLedgerRepository ledgerRepository;
    @Mock private WithdrawalRepository withdrawalRepository;
    @Mock private Wallet wallet;
    private WalletAccountService service;

    @BeforeEach
    void setUp() {
        service = new WalletAccountService(
                walletRepository,
                ledgerRepository,
                withdrawalRepository,
                TestPaymentProperties.defaults()
        );
    }

    @Test
    void calculatesAvailableBalanceAfterReservedWithdrawals() {
        UUID walletId = UUID.randomUUID();
        when(wallet.getId()).thenReturn(walletId);
        when(wallet.getCurrencyCode()).thenReturn("USD");
        when(ledgerRepository.balance(walletId, LedgerDirection.CREDIT)).thenReturn(10_000L);
        when(withdrawalRepository.reservedAmount(any(), any())).thenReturn(3_000L);

        assertThat(service.balance(wallet))
                .isEqualTo(new WalletBalance(10_000, 7_000, "USD"));
    }

    @Test
    void duplicateDebitIsIdempotentWithoutCheckingBalanceAgain() {
        UUID walletId = UUID.randomUUID();
        WalletEntryCommand command = command(2_000, "same-key");
        when(wallet.getId()).thenReturn(walletId);
        when(ledgerRepository.findByWallet_IdAndIdempotencyKey(walletId, "same-key"))
                .thenReturn(Optional.of(org.mockito.Mockito.mock(WalletLedgerEntry.class)));

        service.debit(wallet, command);

        verify(ledgerRepository, never()).save(any());
        verify(withdrawalRepository, never()).reservedAmount(any(), any());
    }

    @Test
    void rejectsDebitAboveAvailableBalance() {
        UUID walletId = UUID.randomUUID();
        when(wallet.getId()).thenReturn(walletId);
        when(wallet.getCurrencyCode()).thenReturn("USD");
        when(ledgerRepository.findByWallet_IdAndIdempotencyKey(walletId, "debit-key"))
                .thenReturn(Optional.empty());
        when(ledgerRepository.balance(walletId, LedgerDirection.CREDIT)).thenReturn(1_000L);
        when(withdrawalRepository.reservedAmount(any(), any())).thenReturn(0L);

        assertThatThrownBy(() -> service.debit(wallet, command(1_001, "debit-key")))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INSUFFICIENT_WALLET_BALANCE));
    }

    @Test
    void recordsCreditWithCanonicalLedgerDirection() {
        UUID walletId = UUID.randomUUID();
        when(wallet.getId()).thenReturn(walletId);
        when(ledgerRepository.findByWallet_IdAndIdempotencyKey(walletId, "credit-key"))
                .thenReturn(Optional.empty());
        ArgumentCaptor<WalletLedgerEntry> entry = ArgumentCaptor.forClass(WalletLedgerEntry.class);

        service.credit(wallet, command(500, "credit-key"));

        verify(ledgerRepository).save(entry.capture());
        assertThat(entry.getValue().getDirection()).isEqualTo(LedgerDirection.CREDIT);
        assertThat(entry.getValue().getAmountMinor()).isEqualTo(500);
    }

    private WalletEntryCommand command(long amount, String key) {
        return new WalletEntryCommand(
                amount,
                LedgerEntryType.TOP_UP,
                "PAYMENT",
                UUID.randomUUID(),
                key,
                Instant.parse("2026-09-24T12:00:00Z")
        );
    }
}
