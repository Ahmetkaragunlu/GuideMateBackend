package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class SavedPaymentMethodStateTest {

    @Test
    void preservesProviderMetadataWhenPaymentRetrieveReturnsOnlyPartialCardDetails() {
        SavedPaymentMethod method = new SavedPaymentMethod(
                new User(),
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
                ),
                true
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
        assertThat(method.isDefaultMethod()).isTrue();
    }

    @Test
    void deletedCardCannotRemainDefault() {
        SavedPaymentMethod method = new SavedPaymentMethod(
                new User(),
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
                ),
                true
        );

        method.markDeleted();

        assertThat(method.getStatus()).isEqualTo(SavedPaymentMethodStatus.DELETED);
        assertThat(method.isDefaultMethod()).isFalse();
        assertThat(method.getDefaultGuard()).isNull();
        assertThatIllegalStateException().isThrownBy(() -> method.setDefault(true));
    }
}
