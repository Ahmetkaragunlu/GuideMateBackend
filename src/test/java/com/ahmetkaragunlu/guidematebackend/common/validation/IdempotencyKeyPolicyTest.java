package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdempotencyKeyPolicyTest {

    private final IdempotencyKeyPolicy policy = new IdempotencyKeyPolicy();

    @Test
    void trimsValidKey() {
        assertThat(policy.normalize("  checkout-123  ")).isEqualTo("checkout-123");
    }

    @Test
    void rejectsBlankOrOversizedKey() {
        assertValidationFailure("   ");
        assertValidationFailure("x".repeat(IdempotencyKeyPolicy.MAX_LENGTH + 1));
    }

    private void assertValidationFailure(String value) {
        assertThatThrownBy(() -> policy.normalize(value))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.VALIDATION_FAILED));
    }
}
