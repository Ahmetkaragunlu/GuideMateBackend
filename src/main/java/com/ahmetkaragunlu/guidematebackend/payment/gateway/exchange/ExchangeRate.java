package com.ahmetkaragunlu.guidematebackend.payment.gateway.exchange;

import java.math.BigDecimal;
import java.time.LocalDate;

public record ExchangeRate(
        String baseCurrencyCode,
        String chargeCurrencyCode,
        BigDecimal rate,
        String source,
        LocalDate rateDate
) {
}
