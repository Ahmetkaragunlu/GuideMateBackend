package com.ahmetkaragunlu.guidematebackend.payment.gateway.provider;

import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.checkout.HostedCheckoutCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.checkout.HostedCheckoutSession;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.refund.ProviderRefundCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.refund.ProviderRefundResult;

public interface HostedPaymentGateway {

    HostedCheckoutSession initialize(HostedCheckoutCommand command);

    VerifiedPaymentResult retrieve(String token, String conversationId);

    ProviderRefundResult refund(ProviderRefundCommand command);
}
