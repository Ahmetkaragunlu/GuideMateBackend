package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import java.util.UUID;

final class DemoFixtureData {

    private DemoFixtureData() {
    }

    record Media(
            UUID id,
            long ownerId,
            String purpose,
            String storageKey,
            String originalFileName,
            String contentType,
            long sizeBytes
    ) {
    }

    record BankAccount(
            UUID id,
            long guideId,
            int ordinal,
            String ibanEncrypted,
            String ibanFingerprint,
            String maskedIban,
            String bankCode,
            String bankName,
            String accountHolderName
    ) {
    }
}
