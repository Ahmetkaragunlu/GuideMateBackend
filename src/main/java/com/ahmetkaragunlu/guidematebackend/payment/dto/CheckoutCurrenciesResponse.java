package com.ahmetkaragunlu.guidematebackend.payment.dto;

import java.util.List;

public record CheckoutCurrenciesResponse(
        String baseCurrencyCode,
        List<CheckoutCurrencyOptionResponse> chargeCurrencies
) {
}
