package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TurkishIbanPolicyTest {

    private final TurkishIbanPolicy policy = new TurkishIbanPolicy();

    @Test
    void normalizesAndValidatesTurkishIban() {
        ValidatedIban iban = policy.validate("tr25 0006 4000 0000 0000 0000 01");

        assertThat(iban.normalizedIban()).isEqualTo("TR250006400000000000000001");
        assertThat(iban.bankCode()).isEqualTo("00064");
        assertThat(iban.bankName()).isEqualTo("Turkiye Is Bankasi");
        assertThat(iban.maskedIban()).doesNotContain("0000000000000001");
    }

    @Test
    void rejectsInvalidCheckDigits() {
        assertThatThrownBy(() -> policy.validate("TR260006400000000000000001"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.BANK_ACCOUNT_INVALID));
    }
}
