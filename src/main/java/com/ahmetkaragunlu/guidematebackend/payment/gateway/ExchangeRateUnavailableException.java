package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public class ExchangeRateUnavailableException extends RuntimeException {

    public ExchangeRateUnavailableException(Throwable cause) {
        super(cause);
    }

    public ExchangeRateUnavailableException() {
        super();
    }
}
