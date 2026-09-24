package com.ahmetkaragunlu.guidematebackend.common.config;

import com.ahmetkaragunlu.guidematebackend.support.TestPaymentProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProductionConfigurationValidatorTest {

    @Test
    void acceptsPublicHttpsUrls() {
        ProductionConfigurationValidator validator = validator(
                "https://api.guidemate.example",
                "https://payments.guidemate.example"
        );

        assertThatCode(validator::validate).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://api.guidemate.example",
            "https://localhost:8080",
            "https://127.0.0.1",
            "https://10.1.2.3",
            "https://172.16.1.2",
            "https://172.31.255.254",
            "https://192.168.68.103",
            "https://backend.local"
    })
    void rejectsNonHttpsOrPrivateProductionUrl(String publicBaseUrl) {
        ProductionConfigurationValidator validator = validator(
                publicBaseUrl,
                "https://payments.guidemate.example"
        );

        assertThatThrownBy(validator::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Production PUBLIC_BASE_URL must be a public HTTPS URL");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            " ",
            "not-a-url",
            "http://payments.guidemate.example",
            "https://localhost:8080",
            "https://127.0.0.1",
            "https://10.1.2.3",
            "https://172.16.1.2",
            "https://172.31.255.254",
            "https://192.168.68.103",
            "https://payments.local"
    })
    void rejectsBlankMalformedNonHttpsOrPrivatePaymentCallbackUrl(String callbackBaseUrl) {
        ProductionConfigurationValidator validator = validator(
                "https://api.guidemate.example",
                callbackBaseUrl
        );

        assertThatThrownBy(validator::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Production PAYMENT_CALLBACK_BASE_URL must be a public HTTPS URL");
    }

    private ProductionConfigurationValidator validator(String publicBaseUrl, String callbackBaseUrl) {
        return new ProductionConfigurationValidator(
                new AppProperties(URI.create(publicBaseUrl)),
                TestPaymentProperties.withCallbackBaseUrl(callbackBaseUrl)
        );
    }
}
