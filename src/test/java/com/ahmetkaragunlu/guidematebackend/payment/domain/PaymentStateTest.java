package com.ahmetkaragunlu.guidematebackend.payment.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class PaymentStateTest {

    @Test
    void preservesLateProviderSuccessAfterLocalCancellation() {
        Payment payment = Payment.hosted(
                new User(),
                PaymentPurpose.WALLET_TOP_UP,
                null,
                1000,
                "USD",
                "top-up-key"
        );

        payment.cancel();
        payment.succeed("provider-payment", "provider-transaction", Instant.parse("2026-08-10T00:00:00Z"));

        assertThat(payment.getStatus()).isEqualTo(PaymentStatus.SUCCEEDED);
        assertThat(payment.getProviderPaymentId()).isEqualTo("provider-payment");
    }

    @Test
    void preservesLateProviderSuccessAfterTimeout() {
        Payment payment = Payment.hosted(
                new User(),
                PaymentPurpose.WALLET_TOP_UP,
                null,
                1000,
                "USD",
                "timeout-key"
        );

        payment.timeout();
        payment.succeed("provider-payment", "provider-transaction", Instant.parse("2026-08-10T00:00:00Z"));

        assertThat(payment.getStatus()).isEqualTo(PaymentStatus.SUCCEEDED);
    }
}
