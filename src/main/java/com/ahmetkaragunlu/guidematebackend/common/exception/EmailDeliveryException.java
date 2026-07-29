package com.ahmetkaragunlu.guidematebackend.common.exception;

public class EmailDeliveryException extends BusinessException {

    public EmailDeliveryException(Throwable cause) {
        super(ErrorCode.EMAIL_DELIVERY_FAILED, cause);
    }
}
