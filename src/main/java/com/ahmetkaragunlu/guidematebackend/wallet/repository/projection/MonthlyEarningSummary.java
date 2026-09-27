package com.ahmetkaragunlu.guidematebackend.wallet.repository.projection;

public interface MonthlyEarningSummary {

    Integer getYear();

    Integer getMonth();

    Long getNetEarningsMinor();

    String getCurrencyCode();

    Long getPendingEarningsMinor();
}
