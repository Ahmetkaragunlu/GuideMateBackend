package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VersionPolicyTest {

    private final VersionPolicy versionPolicy = new VersionPolicy();

    @Test
    void acceptsMatchingVersion() {
        assertThatCode(() -> versionPolicy.requireMatch(4L, 4L))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsStaleVersion() {
        assertThatThrownBy(() -> versionPolicy.requireMatch(5L, 4L))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CONCURRENT_UPDATE)
                );
    }
}
