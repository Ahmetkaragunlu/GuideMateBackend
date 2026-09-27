package com.ahmetkaragunlu.guidematebackend.wallet.dto.response;

public record MonthlyGuideEarningResponse(
        int year,
        int month,
        long netEarningsMinor,
        String currencyCode,
        long pendingEarningsMinor
) {
}
