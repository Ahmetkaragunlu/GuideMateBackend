package com.ahmetkaragunlu.guidematebackend.tour.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TourInputPolicyTest {

    private final TourInputPolicy policy = new TourInputPolicy();

    @Test
    void normalizesSupportedCategoryAndCountry() {
        assertThat(policy.normalizeCategoryCode(" CULTURE ")).isEqualTo("culture");
        assertThat(policy.normalizeCountryCode(" tr ")).isEqualTo("TR");
    }

    @Test
    void rejectsUnknownCodesAndOffsetOnlyTimeZone() {
        assertError(() -> policy.normalizeCategoryCode("unknown"), ErrorCode.INVALID_CATEGORY_CODE);
        assertError(() -> policy.normalizeCountryCode("XX"), ErrorCode.INVALID_COUNTRY_CODE);
        assertError(() -> policy.validateTimeZoneId("+03:00"), ErrorCode.INVALID_TIME_ZONE);
    }

    @Test
    void acceptsCanonicalRegionTimeZone() {
        assertThat(policy.validateTimeZoneId("Europe/Istanbul")).isEqualTo("Europe/Istanbul");
    }

    private void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, ErrorCode expected) {
        assertThatThrownBy(action)
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(expected));
    }
}
