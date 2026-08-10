package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderCardDetails;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.VerifiedPaymentResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentVerificationServiceTest {

    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private PaymentIntentService paymentIntentService;
    @Mock
    private PaymentResultService paymentResultService;
    @Mock
    private HostedPaymentGateway paymentGateway;
    @Mock
    private SensitiveDataCipher dataCipher;
    @Mock
    private SavedPaymentMethodStateService savedPaymentMethodStateService;

    private PaymentVerificationService service;

    @BeforeEach
    void setUp() {
        service = new PaymentVerificationService(
                paymentRepository,
                paymentIntentService,
                paymentResultService,
                paymentGateway,
                dataCipher,
                savedPaymentMethodStateService
        );
    }

    @Test
    void capturesProviderCardOnlyAfterSuccessfulPaymentApplication() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        User user = mock(User.class);
        ProviderCardDetails providerCard = providerCard();
        VerifiedPaymentResult result = result(true, providerCard);
        when(dataCipher.fingerprint("checkout-token")).thenReturn("token-fingerprint");
        when(paymentRepository.findByProviderTokenFingerprint("token-fingerprint"))
                .thenReturn(Optional.of(payment));
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getProviderConversationId()).thenReturn("conversation-id");
        when(paymentGateway.retrieve("checkout-token", "conversation-id")).thenReturn(result);
        when(paymentResultService.apply(eq(paymentId), eq(result), any(ProviderVerifiedEvent.class)))
                .thenReturn(payment);
        when(payment.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(42L);

        Payment verified = service.verifyToken("checkout-token", "CALLBACK", "event-seed");

        assertThat(verified).isSameAs(payment);
        verify(savedPaymentMethodStateService).capture(42L, providerCard);
    }

    @Test
    void doesNotCaptureCardFromFailedPaymentResult() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        VerifiedPaymentResult result = result(false, null);
        when(dataCipher.fingerprint("checkout-token")).thenReturn("token-fingerprint");
        when(paymentRepository.findByProviderTokenFingerprint("token-fingerprint"))
                .thenReturn(Optional.of(payment));
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getProviderConversationId()).thenReturn("conversation-id");
        when(paymentGateway.retrieve("checkout-token", "conversation-id")).thenReturn(result);
        when(paymentResultService.apply(eq(paymentId), eq(result), any(ProviderVerifiedEvent.class)))
                .thenReturn(payment);

        service.verifyToken("checkout-token", "WEBHOOK", "event-seed");

        verify(savedPaymentMethodStateService, never()).capture(any(), any());
    }

    private VerifiedPaymentResult result(boolean successful, ProviderCardDetails providerCard) {
        return new VerifiedPaymentResult(
                successful,
                "checkout-token",
                "conversation-id",
                "provider-payment-id",
                "provider-transaction-id",
                10_000,
                "USD",
                successful ? "SUCCESS" : "FAILURE",
                successful ? null : "DECLINED",
                providerCard
        );
    }

    private ProviderCardDetails providerCard() {
        return new ProviderCardDetails(
                "customer-key",
                "card-token",
                null,
                "Example Bank",
                null,
                "Example Family",
                "MASTER_CARD",
                "CREDIT_CARD",
                "0006",
                null,
                null,
                null
        );
    }
}
