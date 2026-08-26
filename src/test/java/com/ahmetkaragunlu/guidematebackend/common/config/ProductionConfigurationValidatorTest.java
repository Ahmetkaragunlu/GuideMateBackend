package com.ahmetkaragunlu.guidematebackend.common.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProductionConfigurationValidatorTest {

    @Test
    void acceptsPublicHttpsUrl() {
        ProductionConfigurationValidator validator = new ProductionConfigurationValidator(
                "https://api.guidemate.example"
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
        ProductionConfigurationValidator validator = new ProductionConfigurationValidator(publicBaseUrl);

        assertThatThrownBy(validator::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Production PUBLIC_BASE_URL must be a public HTTPS URL");
    }
}
