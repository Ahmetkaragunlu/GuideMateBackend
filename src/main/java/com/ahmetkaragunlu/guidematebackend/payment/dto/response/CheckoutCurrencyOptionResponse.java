package com.ahmetkaragunlu.guidematebackend.payment.dto.response;

public record CheckoutCurrencyOptionResponse(
        String currencyCode,
        int fractionDigits
) {
}
