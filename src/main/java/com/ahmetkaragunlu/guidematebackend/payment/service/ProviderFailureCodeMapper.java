package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

@Component
public class ProviderFailureCodeMapper {

    private static final String IYZICO_INSUFFICIENT_FUNDS = "10051";

    public String toStableCode(String providerCode) {
        return IYZICO_INSUFFICIENT_FUNDS.equals(providerCode)
                ? ErrorCode.CARD_INSUFFICIENT_FUNDS.name()
                : ErrorCode.PAYMENT_METHOD_DECLINED.name();
    }
}
