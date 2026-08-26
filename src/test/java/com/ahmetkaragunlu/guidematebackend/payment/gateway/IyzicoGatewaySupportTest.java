package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IyzicoGatewaySupportTest {

    @Test
    void returnsSuccessfulProviderResult() {
        assertThat(IyzicoGatewaySupport.execute(() -> "provider-result"))
                .isEqualTo("provider-result");
    }

    @Test
    void preservesKnownGatewayFailure() {
        PaymentGatewayException failure = new PaymentGatewayException("PAYMENT_DECLINED");

        assertThatThrownBy(() -> IyzicoGatewaySupport.execute(() -> {
            throw failure;
        })).isSameAs(failure);
    }

    @Test
    void wrapsUnexpectedProviderFailureAndPreservesCause() {
        IllegalStateException cause = new IllegalStateException("provider SDK failed");

        assertThatThrownBy(() -> IyzicoGatewaySupport.execute(() -> {
            throw cause;
        })).isInstanceOfSatisfying(PaymentGatewayException.class, exception -> {
            assertThat(exception.providerFailureCode()).isEqualTo("PROVIDER_UNAVAILABLE");
            assertThat(exception.getCause()).isSameAs(cause);
        });
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void normalizesMissingProviderFailureCode(String failureCode) {
        assertThat(IyzicoGatewaySupport.normalizeFailureCode(failureCode))
                .isEqualTo("PROVIDER_REJECTED");
    }

    @Test
    void trimsProviderFailureCode() {
        assertThat(IyzicoGatewaySupport.normalizeFailureCode("  PAYMENT_DECLINED  "))
                .isEqualTo("PAYMENT_DECLINED");
    }
}
