package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

@Component
public class IdempotencyKeyPolicy {

    public static final int MAX_LENGTH = 128;

    public String normalize(String value) {
        if (value == null || value.isBlank() || value.length() > MAX_LENGTH) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
        return value.trim();
    }
}
