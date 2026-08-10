package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;

public interface BuyerProfileProvider {

    BuyerProfile get(User user);
}
