package com.ahmetkaragunlu.guidematebackend.payment.config;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PaymentPropertiesTest {

    @Test
    void normalizesEnabledCurrenciesAndBuildsPublicCallback() {
        PaymentProperties properties = properties("https://payments.example.com/", Set.of(" usd ", "try"));

        assertThat(properties.fx().enabledChargeCurrencies()).containsExactlyInAnyOrder("USD", "TRY");
        assertThat(properties.callbackUri("/callback")).isEqualTo(URI.create("https://payments.example.com/callback"));
    }

    @Test
    void rejectsUnsupportedCurrencyAndNonHttpsProviderUrl() {
        assertThatThrownBy(() -> properties("https://payments.example.com", Set.of("USD", "CAD")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PaymentProperties.Iyzico("key", "secret", "http://sandbox.example.com"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsHostedCallbackWithoutPublicHttpsUrl() {
        PaymentProperties properties = properties("http://localhost:8080", Set.of("USD"));

        assertThatThrownBy(() -> properties.callbackUri("/callback"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("public HTTPS");
    }

    private PaymentProperties properties(String callbackBaseUrl, Set<String> currencies) {
        return new PaymentProperties(
                "USD",
                Duration.ofMinutes(30),
                callbackBaseUrl,
                new PaymentProperties.Fx(
                        URI.create("https://api.frankfurter.app"),
                        Duration.ofMinutes(10),
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        currencies,
                        "frankfurter"
                ),
                new PaymentProperties.Iyzico("key", "secret", "https://sandbox-api.iyzipay.com"),
                PayoutMode.SIMULATED,
                1000,
                new PaymentProperties.SandboxBuyer(false, null, null, null, null, null, null, null)
        );
    }
}
