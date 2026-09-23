package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.support.TestPaymentProperties;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Withdrawal;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WithdrawalRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WithdrawalServiceTest {

    @Mock private WithdrawalRepository repository;
    @Mock private WalletAccountService walletService;
    @Mock private BankAccountService bankAccountService;
    @Mock private IdempotencyKeyPolicy idempotencyKeyPolicy;
    @Mock private NotificationPublisher notificationPublisher;
    @Mock private User guide;
    @Mock private Wallet wallet;
    private WithdrawalService service;

    @BeforeEach
    void setUp() {
        service = new WithdrawalService(
                repository,
                walletService,
                bankAccountService,
                idempotencyKeyPolicy,
                TestPaymentProperties.defaults(),
                notificationPublisher,
                Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void returnsPreviousWithdrawalForSameRequest() {
        UUID walletId = UUID.randomUUID();
        UUID bankId = UUID.randomUUID();
        Withdrawal previous = org.mockito.Mockito.mock(Withdrawal.class);
        BankAccount bank = org.mockito.Mockito.mock(BankAccount.class);
        when(idempotencyKeyPolicy.normalize(" key ")).thenReturn("key");
        when(walletService.getOrCreateForUpdate(guide)).thenReturn(wallet);
        when(wallet.getId()).thenReturn(walletId);
        when(repository.findByWallet_IdAndIdempotencyKey(walletId, "key"))
                .thenReturn(Optional.of(previous));
        when(previous.getBankAccount()).thenReturn(bank);
        when(bank.getId()).thenReturn(bankId);
        when(previous.getAmountMinor()).thenReturn(2_000L);

        assertThat(service.request(guide, bankId, 2_000, " key ")).isSameAs(previous);
        verify(bankAccountService, never()).requireOwnedActiveForUpdate(guide, bankId);
    }

    @Test
    void rejectsAmountAboveWithdrawableBalanceBeforeCreatingRecord() {
        UUID walletId = UUID.randomUUID();
        UUID bankId = UUID.randomUUID();
        BankAccount bank = org.mockito.Mockito.mock(BankAccount.class);
        when(idempotencyKeyPolicy.normalize("key")).thenReturn("key");
        when(walletService.getOrCreateForUpdate(guide)).thenReturn(wallet);
        when(wallet.getId()).thenReturn(walletId);
        when(repository.findByWallet_IdAndIdempotencyKey(walletId, "key")).thenReturn(Optional.empty());
        when(bankAccountService.requireOwnedActiveForUpdate(guide, bankId)).thenReturn(bank);
        when(walletService.balance(wallet)).thenReturn(new WalletBalance(5_000, 1_000, "USD"));

        assertThatThrownBy(() -> service.request(guide, bankId, 1_001, "key"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode())
                                .isEqualTo(ErrorCode.INSUFFICIENT_WITHDRAWABLE_BALANCE));
        verify(repository, never()).saveAndFlush(org.mockito.ArgumentMatchers.any());
    }
}
