package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProviderFailureCodeMapperTest {

    private final ProviderFailureCodeMapper mapper = new ProviderFailureCodeMapper();

    @Test
    void mapsInsufficientFundsToStablePublicCode() {
        assertThat(mapper.toStableCode("10051"))
                .isEqualTo(ErrorCode.CARD_INSUFFICIENT_FUNDS.name());
    }

    @Test
    void hidesUnknownProviderDeclineBehindGenericStableCode() {
        assertThat(mapper.toStableCode("provider-sensitive-code"))
                .isEqualTo(ErrorCode.PAYMENT_METHOD_DECLINED.name());
    }
}
