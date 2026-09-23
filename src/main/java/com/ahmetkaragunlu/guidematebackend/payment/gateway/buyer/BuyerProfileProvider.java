package com.ahmetkaragunlu.guidematebackend.payment.gateway.buyer;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;

public interface BuyerProfileProvider {

    BuyerProfile get(User user);
}
