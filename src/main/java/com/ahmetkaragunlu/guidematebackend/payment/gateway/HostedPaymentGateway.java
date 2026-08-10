package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public interface HostedPaymentGateway {

    HostedCheckoutSession initialize(HostedCheckoutCommand command);

    VerifiedPaymentResult retrieve(String token, String conversationId);

    ProviderRefundResult refund(ProviderRefundCommand command);
}
