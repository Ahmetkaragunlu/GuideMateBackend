package com.ahmetkaragunlu.guidematebackend.payment.gateway.exchange;

public interface ExchangeRateProvider {

    ExchangeRate latest(String baseCurrencyCode, String chargeCurrencyCode);
}
