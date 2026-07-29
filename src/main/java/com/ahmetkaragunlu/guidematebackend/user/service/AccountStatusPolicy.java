package com.ahmetkaragunlu.guidematebackend.user.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class AccountStatusPolicy {

    public Optional<ErrorCode> accessError(User user) {
        return switch (user.getAccountStatus()) {
            case ACTIVE -> Optional.empty();
            case PENDING_VERIFICATION -> Optional.of(ErrorCode.ACCOUNT_PENDING_VERIFICATION);
            case DISABLED -> Optional.of(ErrorCode.ACCOUNT_DISABLED);
        };
    }

    public void requireActive(User user) {
        accessError(user).ifPresent(errorCode -> {
            throw new BusinessException(errorCode);
        });
    }
}
