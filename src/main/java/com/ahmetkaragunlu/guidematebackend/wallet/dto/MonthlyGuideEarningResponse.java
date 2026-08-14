package com.ahmetkaragunlu.guidematebackend.wallet.dto;

public record MonthlyGuideEarningResponse(
        int year,
        int month,
        long netEarningsMinor,
        String currencyCode
) {
}
