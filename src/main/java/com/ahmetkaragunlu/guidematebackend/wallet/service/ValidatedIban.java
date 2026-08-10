package com.ahmetkaragunlu.guidematebackend.wallet.service;

public record ValidatedIban(
        String normalizedIban,
        String maskedIban,
        String bankCode,
        String bankName
) {
}
