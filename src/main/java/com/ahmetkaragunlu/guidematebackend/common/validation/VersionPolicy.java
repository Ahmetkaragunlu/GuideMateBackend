package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

@Component
public class VersionPolicy {

    public void requireMatch(long actualVersion, long requestedVersion) {
        if (actualVersion != requestedVersion) {
            throw new BusinessException(ErrorCode.CONCURRENT_UPDATE);
        }
    }
}
