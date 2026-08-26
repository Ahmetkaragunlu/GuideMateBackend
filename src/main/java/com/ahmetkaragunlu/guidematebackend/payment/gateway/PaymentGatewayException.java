package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public class PaymentGatewayException extends RuntimeException {

    private final String providerFailureCode;

    public PaymentGatewayException(String providerFailureCode) {
        super("Payment provider operation failed");
        this.providerFailureCode = providerFailureCode;
    }

    public PaymentGatewayException(String providerFailureCode, Throwable cause) {
        super("Payment provider operation failed", cause);
        this.providerFailureCode = providerFailureCode;
    }

    public String providerFailureCode() {
        return providerFailureCode;
    }
}
