package com.ahmetkaragunlu.guidematebackend.payment.service.quote;

import java.math.BigDecimal;
import java.time.LocalDate;

public record FxCalculation(
        long chargeAmountMinor,
        String chargeCurrencyCode,
        BigDecimal rate,
        String rateSource,
        LocalDate rateDate
) {
}
