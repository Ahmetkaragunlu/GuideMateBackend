package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Withdrawal;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WithdrawalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class WithdrawalService {

    private final WithdrawalRepository withdrawalRepository;
    private final WalletAccountService walletAccountService;
    private final BankAccountService bankAccountService;
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final PaymentProperties paymentProperties;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

    @Transactional
    public Withdrawal request(
            User guide,
            UUID bankAccountId,
            long amountMinor,
            String idempotencyKey
    ) {
        if (amountMinor <= 0) {
            throw new BusinessException(ErrorCode.INVALID_AMOUNT);
        }
        if (paymentProperties.payoutMode() != PayoutMode.SIMULATED) {
            throw new BusinessException(ErrorCode.PAYMENT_INITIALIZATION_FAILED);
        }
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
        Wallet wallet = walletAccountService.getOrCreateForUpdate(guide);
        Withdrawal previous = withdrawalRepository.findByWallet_IdAndIdempotencyKey(
                wallet.getId(),
                normalizedKey
        ).orElse(null);
        if (previous != null) {
            if (previous.getBankAccount().getId().equals(bankAccountId)
                    && previous.getAmountMinor() == amountMinor) {
                return previous;
            }
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }
        BankAccount bankAccount = bankAccountService.requireOwnedActiveForUpdate(guide, bankAccountId);
        if (walletAccountService.balance(wallet).availableBalanceMinor() < amountMinor) {
            throw new BusinessException(ErrorCode.INSUFFICIENT_WITHDRAWABLE_BALANCE);
        }
        Instant now = clock.instant();
        Withdrawal withdrawal = withdrawalRepository.saveAndFlush(new Withdrawal(
                wallet,
                bankAccount,
                amountMinor,
                PayoutMode.SIMULATED,
                normalizedKey,
                now
        ));
        withdrawal.markProcessing();
        walletAccountService.recordMandatoryDebit(
                wallet,
                amountMinor,
                LedgerEntryType.WITHDRAWAL,
                "WITHDRAWAL",
                withdrawal.getId(),
                "withdrawal-debit:" + withdrawal.getId(),
                now
        );
        withdrawal.complete("SIMULATED-" + withdrawal.getId(), now);
        notificationPublisher.publish(new NotificationCommand(
                guide.getId(),
                NotificationType.WITHDRAWAL_COMPLETED,
                null,
                Map.of(
                        "withdrawalId", withdrawal.getId().toString(),
                        "bankAccountId", bankAccount.getId().toString(),
                        "amountMinor", withdrawal.getAmountMinor(),
                        "currencyCode", withdrawal.getCurrencyCode()
                )
        ));
        return withdrawal;
    }

    @Transactional(readOnly = true)
    public Page<Withdrawal> getHistory(User guide, int page, int size) {
        return withdrawalRepository.findByWallet_User_IdOrderByRequestedAtDesc(
                guide.getId(),
                PageRequest.of(page, size)
        );
    }
}
