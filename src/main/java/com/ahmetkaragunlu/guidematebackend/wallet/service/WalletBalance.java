package com.ahmetkaragunlu.guidematebackend.wallet.service;

public record WalletBalance(
        long balanceMinor,
        long availableBalanceMinor,
        String currencyCode
) {
}
