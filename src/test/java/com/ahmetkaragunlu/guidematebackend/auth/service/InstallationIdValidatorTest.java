package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InstallationIdValidatorTest {

    private final InstallationIdValidator validator = new InstallationIdValidator();

    @Test
    void returnsCanonicalUuid() {
        String installationId = "550e8400-e29b-41d4-a716-446655440000";

        assertThat(validator.validate(installationId)).isEqualTo(installationId);
    }

    @Test
    void normalizesUppercaseUuid() {
        assertThat(validator.validate("550E8400-E29B-41D4-A716-446655440000"))
                .isEqualTo("550e8400-e29b-41d4-a716-446655440000");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1", " 550e8400-e29b-41d4-a716-446655440000 "})
    void rejectsMissingMalformedOrNonCanonicalValue(String installationId) {
        assertThatThrownBy(() -> validator.validate(installationId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_INSTALLATION_ID));
    }
}
