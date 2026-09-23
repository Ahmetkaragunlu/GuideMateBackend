package com.ahmetkaragunlu.guidematebackend.payment.service.refund;

import com.ahmetkaragunlu.guidematebackend.payment.event.RefundRequestedEvent;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.ProviderRefundCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.ProviderRefundResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentRefundProcessorTest {

    @Mock private PaymentRefundStateService stateService;
    @Mock private HostedPaymentGateway gateway;
    private PaymentRefundProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new PaymentRefundProcessor(stateService, gateway);
    }

    @Test
    void completesStartedProviderRefund() {
        UUID refundId = UUID.randomUUID();
        RefundRequestedEvent event = new RefundRequestedEvent(refundId);
        RefundProcessingCommand command = command(refundId);
        ProviderRefundResult result = new ProviderRefundResult(true, "provider-refund", null);
        when(stateService.begin(refundId)).thenReturn(command);
        when(gateway.refund(any(ProviderRefundCommand.class))).thenReturn(result);

        processor.process(event);

        verify(stateService).complete(refundId, result);
    }

    @Test
    void marksProviderExceptionUncertainForSafeRecovery() {
        UUID refundId = UUID.randomUUID();
        RefundRequestedEvent event = new RefundRequestedEvent(refundId);
        when(stateService.begin(refundId)).thenReturn(command(refundId));
        when(gateway.refund(any())).thenThrow(new IllegalStateException("provider timeout"));

        processor.process(event);

        verify(stateService).markUncertain(refundId);
        verify(stateService, never()).complete(any(), any());
    }

    @Test
    void ignoresRefundThatCannotBeStarted() {
        UUID refundId = UUID.randomUUID();
        processor.process(new RefundRequestedEvent(refundId));
        verify(gateway, never()).refund(any());
    }

    private RefundProcessingCommand command(UUID refundId) {
        return new RefundProcessingCommand(
                refundId,
                "conversation",
                "transaction",
                1_000,
                "TRY",
                "127.0.0.1"
        );
    }
}
