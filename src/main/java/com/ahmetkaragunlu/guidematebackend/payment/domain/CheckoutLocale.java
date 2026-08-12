package com.ahmetkaragunlu.guidematebackend.payment.domain;

public enum CheckoutLocale {
    TR("tr"),
    EN("en");

    private final String providerValue;

    CheckoutLocale(String providerValue) {
        this.providerValue = providerValue;
    }

    public String providerValue() {
        return providerValue;
    }
}
