package com.ahmetkaragunlu.guidematebackend.wallet.repository;

public interface MonthlyEarningSummary {

    Integer getYear();

    Integer getMonth();

    Long getNetEarningsMinor();

    String getCurrencyCode();
}
