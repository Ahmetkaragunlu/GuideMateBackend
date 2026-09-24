package com.ahmetkaragunlu.guidematebackend.support;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;

import java.net.URI;
import java.time.Duration;
import java.util.Set;

public final class TestPaymentProperties {

    private TestPaymentProperties() {
    }

    public static PaymentProperties defaults() {
        return withCallbackBaseUrl("https://payments.guidemate.test");
    }

    public static PaymentProperties withCallbackBaseUrl(String callbackBaseUrl) {
        return new PaymentProperties(
                "USD",
                Duration.ofMinutes(30),
                callbackBaseUrl,
                new PaymentProperties.Fx(
                        URI.create("https://api.frankfurter.dev"),
                        Duration.ofMinutes(10),
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(5),
                        Set.of("USD", "TRY", "EUR"),
                        "ECB"
                ),
                new PaymentProperties.Iyzico("api-key", "secret-key", "https://sandbox-api.iyzipay.com"),
                PayoutMode.SIMULATED,
                1000,
                new PaymentProperties.SandboxBuyer(
                        true,
                        "11111111111",
                        "+905555555555",
                        "Test adresi",
                        "Istanbul",
                        "Turkey",
                        "34000",
                        "127.0.0.1"
                )
        );
    }
}
