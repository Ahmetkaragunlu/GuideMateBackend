package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SavedPaymentMethodStateTest {

    @Test
    void preservesProviderMetadataWhenPaymentRetrieveReturnsOnlyPartialCardDetails() {
        SavedPaymentMethod method = new SavedPaymentMethod(
                testUser(),
                "encrypted-token",
                "fingerprint",
                new SavedCardMetadata(
                        "Travel card",
                        "Example Bank",
                        "46",
                        "Example Family",
                        "MASTER_CARD",
                        "CREDIT_CARD",
                        "0006",
                        "Test User",
                        (short) 12,
                        (short) 2033
                )
        );

        method.refreshMetadata(new SavedCardMetadata(
                null,
                "Updated Bank",
                null,
                null,
                "MASTER_CARD",
                "CREDIT_CARD",
                "0006",
                null,
                null,
                null
        ));

        assertThat(method.getAlias()).isEqualTo("Travel card");
        assertThat(method.getBankName()).isEqualTo("Updated Bank");
        assertThat(method.getExpiryMonth()).isEqualTo((short) 12);
        assertThat(method.getExpiryYear()).isEqualTo((short) 2033);
    }

    @Test
    void marksSavedCardDeletedWithoutChangingProviderMetadata() {
        SavedPaymentMethod method = new SavedPaymentMethod(
                testUser(),
                "encrypted-token",
                "fingerprint",
                new SavedCardMetadata(
                        null,
                        null,
                        null,
                        null,
                        "VISA",
                        "DEBIT_CARD",
                        "1234",
                        null,
                        null,
                        null
                )
        );

        method.markDeleted();

        assertThat(method.getStatus()).isEqualTo(SavedPaymentMethodStatus.DELETED);
        assertThat(method.getLastFourDigits()).isEqualTo("1234");
    }

    private User testUser() {
        return new User("Payment", "Test", "payment@example.com", "not-used");
    }
}
