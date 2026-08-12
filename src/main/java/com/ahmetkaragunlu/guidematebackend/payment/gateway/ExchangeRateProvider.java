package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public interface ExchangeRateProvider {

    ExchangeRate latest(String baseCurrencyCode, String chargeCurrencyCode);
}
