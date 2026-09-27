package com.ahmetkaragunlu.guidematebackend.wallet.dto.response;

public record WalletResponse(
        long balanceMinor,
        long availableBalanceMinor,
        String currencyCode
) {
}
