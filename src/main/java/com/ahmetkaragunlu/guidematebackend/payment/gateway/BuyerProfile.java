package com.ahmetkaragunlu.guidematebackend.payment.gateway;

public record BuyerProfile(
        String id,
        String firstName,
        String lastName,
        String email,
        String identityNumber,
        String phoneNumber,
        String address,
        String city,
        String country,
        String zipCode,
        String ipAddress
) {
}
