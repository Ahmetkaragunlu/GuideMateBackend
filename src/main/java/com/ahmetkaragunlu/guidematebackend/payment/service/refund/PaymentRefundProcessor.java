package com.ahmetkaragunlu.guidematebackend.payment.service.refund;

import com.ahmetkaragunlu.guidematebackend.payment.event.RefundRequestedEvent;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.ProviderRefundCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.ProviderRefundResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PaymentRefundProcessor {

    private final PaymentRefundStateService stateService;
    private final HostedPaymentGateway paymentGateway;

    public void process(RefundRequestedEvent event) {
        RefundProcessingCommand command = stateService.begin(event.refundId());
        if (command == null) {
            return;
        }
        try {
            ProviderRefundResult result = paymentGateway.refund(new ProviderRefundCommand(
                    command.conversationId(),
                    command.providerTransactionId(),
                    command.chargeAmountMinor(),
                    command.chargeCurrencyCode(),
                    command.ipAddress()
            ));
            stateService.complete(command.refundId(), result);
        } catch (RuntimeException exception) {
            stateService.markUncertain(command.refundId());
        }
    }
}
