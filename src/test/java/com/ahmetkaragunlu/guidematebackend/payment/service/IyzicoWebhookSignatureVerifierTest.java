package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.dto.IyzicoWebhookRequest;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.net.URI;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class IyzicoWebhookSignatureVerifierTest {

    private static final String VALID_SIGNATURE =
            "6466ee2dba9e7bd391b3326ac5b945ccad530c4999a98cc4de0ad1ce11785f74";

    private final IyzicoWebhookSignatureVerifier verifier = new IyzicoWebhookSignatureVerifier(
            new PaymentProperties(
                    "USD",
                    Duration.ofMinutes(30),
                    "https://example.test",
                    new PaymentProperties.Fx(
                            URI.create("https://api.frankfurter.dev"),
                            Duration.ofMinutes(10),
                            Duration.ofSeconds(3),
                            Duration.ofSeconds(5),
                            Set.of("USD", "TRY", "EUR", "GBP"),
                            "ECB"
                    ),
                    new PaymentProperties.Iyzico(
                            "test-api-key",
                            "test-secret-key",
                            "https://sandbox-api.iyzipay.com"
                    ),
                    PayoutMode.SIMULATED,
                    1000,
                    new PaymentProperties.SandboxBuyer(
                            true,
                            "11111111111",
                            "+905350000000",
                            "Test address",
                            "Istanbul",
                            "Turkey",
                            "34000",
                            "127.0.0.1"
                    )
            )
    );

    private final IyzicoWebhookRequest request = new IyzicoWebhookRequest(
            "CHECKOUT_FORM_AUTH",
            "1710000000",
            "12345",
            "token-value",
            "guidemate-payment",
            "SUCCESS"
    );

    @Test
    void acceptsValidV3Signature() {
        assertThat(verifier.isValid(VALID_SIGNATURE, request)).isTrue();
    }

    @Test
    void rejectsModifiedPayloadAndMalformedSignature() {
        IyzicoWebhookRequest modified = new IyzicoWebhookRequest(
                request.eventType(),
                request.eventTime(),
                request.paymentId(),
                request.token(),
                request.conversationId(),
                "FAILURE"
        );

        assertThat(verifier.isValid(VALID_SIGNATURE, modified)).isFalse();
        assertThat(verifier.isValid("not-hex", request)).isFalse();
    }
}
