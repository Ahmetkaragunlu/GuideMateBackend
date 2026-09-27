package com.ahmetkaragunlu.guidematebackend.wallet.service.payout;

public record ValidatedIban(
        String normalizedIban,
        String maskedIban,
        String bankCode,
        String bankName
) {
}
