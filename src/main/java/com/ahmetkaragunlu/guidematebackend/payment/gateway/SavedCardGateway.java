package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import java.util.List;

public interface SavedCardGateway {

    List<ProviderCardDetails> list(String customerKey);

    void delete(String customerKey, String cardToken);
}
