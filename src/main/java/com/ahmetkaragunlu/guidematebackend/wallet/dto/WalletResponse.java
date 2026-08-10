package com.ahmetkaragunlu.guidematebackend.wallet.dto;

public record WalletResponse(
        long balanceMinor,
        long availableBalanceMinor,
        String currencyCode
) {
}
