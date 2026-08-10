package com.ahmetkaragunlu.guidematebackend.wallet.mapper;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WalletLedgerEntry;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Withdrawal;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.BankAccountResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.GuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WalletTransactionResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WithdrawalResponse;
import org.springframework.stereotype.Component;

@Component
public class WalletMapper {

    public WalletTransactionResponse toTransaction(WalletLedgerEntry entry) {
        return new WalletTransactionResponse(
                entry.getId(),
                entry.getDirection(),
                entry.getType(),
                entry.getAmountMinor(),
                entry.getWallet().getCurrencyCode(),
                entry.getReferenceType(),
                entry.getReferenceId(),
                entry.getOccurredAt()
        );
    }

    public GuideEarningResponse toEarning(GuideEarning earning) {
        return new GuideEarningResponse(
                earning.getId(),
                earning.getReservation().getId(),
                earning.getGrossMinor(),
                earning.getPlatformFeeMinor(),
                earning.getNetMinor(),
                earning.getCurrencyCode(),
                earning.getStatus(),
                earning.getAvailableAt(),
                earning.getCreatedAt()
        );
    }

    public BankAccountResponse toBankAccount(BankAccount account) {
        return new BankAccountResponse(
                account.getId(),
                account.getMaskedIban(),
                account.getBankCode(),
                account.getBankName(),
                account.getAccountHolderName(),
                account.isDefaultAccount(),
                account.getCreatedAt()
        );
    }

    public WithdrawalResponse toWithdrawal(Withdrawal withdrawal) {
        return new WithdrawalResponse(
                withdrawal.getId(),
                withdrawal.getBankAccount().getId(),
                withdrawal.getBankAccount().getMaskedIban(),
                withdrawal.getAmountMinor(),
                withdrawal.getCurrencyCode(),
                withdrawal.getStatus(),
                withdrawal.getPayoutMode(),
                withdrawal.getRequestedAt(),
                withdrawal.getCompletedAt(),
                withdrawal.getFailureCode()
        );
    }
}
