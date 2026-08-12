package com.ahmetkaragunlu.guidematebackend.payment.dto;

public record CheckoutCurrencyOptionResponse(
        String currencyCode,
        int fractionDigits
) {
}
