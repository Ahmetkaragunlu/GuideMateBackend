package com.ahmetkaragunlu.guidematebackend.wallet.service.account;

public record WalletBalance(
        long balanceMinor,
        long availableBalanceMinor,
        String currencyCode
) {
}
