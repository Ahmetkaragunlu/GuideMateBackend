package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderRefundCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderRefundResult;
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
