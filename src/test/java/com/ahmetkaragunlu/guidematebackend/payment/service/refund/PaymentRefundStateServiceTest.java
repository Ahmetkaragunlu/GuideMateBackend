package com.ahmetkaragunlu.guidematebackend.payment.service.refund;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.ProviderRefundResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.ProviderFailureCodeMapper;
import com.ahmetkaragunlu.guidematebackend.support.TestPaymentProperties;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentRefundStateServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @Mock private RefundRepository refundRepository;
    @Mock private ProviderFailureCodeMapper failureCodeMapper;
    @Mock private RefundNotificationPublisher notificationPublisher;
    private PaymentRefundStateService service;

    @BeforeEach
    void setUp() {
        service = new PaymentRefundStateService(
                refundRepository,
                TestPaymentProperties.defaults(),
                TestSchedulerProperties.defaults(),
                failureCodeMapper,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void beginsRequestedRefundWithOriginalProviderCharge() {
        UUID refundId = UUID.randomUUID();
        Refund refund = mock(Refund.class);
        Payment payment = mock(Payment.class);
        when(refundRepository.findByIdForUpdate(refundId)).thenReturn(Optional.of(refund));
        when(refund.getStatus()).thenReturn(RefundStatus.REQUESTED);
        when(refund.getId()).thenReturn(refundId);
        when(refund.getPayment()).thenReturn(payment);
        when(payment.getProviderTransactionId()).thenReturn("transaction");
        when(refund.getChargeAmountMinor()).thenReturn(47_758L);
        when(refund.getChargeCurrencyCode()).thenReturn("TRY");

        RefundProcessingCommand command = service.begin(refundId);

        assertThat(command.providerTransactionId()).isEqualTo("transaction");
        assertThat(command.chargeAmountMinor()).isEqualTo(47_758L);
        verify(refund).markProcessing(NOW);
    }

    @Test
    void successfulProviderResultIsIdempotent() {
        UUID refundId = UUID.randomUUID();
        Refund refund = mock(Refund.class);
        when(refundRepository.findByIdForUpdate(refundId)).thenReturn(Optional.of(refund));
        when(refund.getStatus()).thenReturn(RefundStatus.SUCCEEDED);

        service.complete(refundId, new ProviderRefundResult(true, "provider-refund", null));

        verify(refund, never()).succeed(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        verify(notificationPublisher, never()).publish(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void uncertainProviderResultRequiresManualReviewOnce() {
        UUID refundId = UUID.randomUUID();
        Refund refund = mock(Refund.class);
        when(refundRepository.findByIdForUpdate(refundId)).thenReturn(Optional.of(refund));
        when(refund.getStatus()).thenReturn(RefundStatus.PROCESSING);

        service.markUncertain(refundId);

        verify(refund).requireManualReview("PROVIDER_RESULT_UNCERTAIN");
        verify(notificationPublisher).publish(refund, NotificationType.REFUND_MANUAL_REVIEW);
    }
}
