package com.ahmetkaragunlu.guidematebackend.payment.gateway.buyer;

public record BuyerProfile(
        // Buyer identity
        String id,
        String firstName,
        String lastName,
        String email,
        String identityNumber,

        // Contact and billing address
        String phoneNumber,
        String address,
        String city,
        String country,
        String zipCode,

        // Request context
        String ipAddress
) {
}
