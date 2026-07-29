package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class InstallationIdValidator {

    public String validate(String installationId) {
        try {
            UUID parsed = UUID.fromString(installationId);
            if (!parsed.toString().equalsIgnoreCase(installationId)) {
                throw new IllegalArgumentException("Non-canonical UUID");
            }
            return parsed.toString();
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new BusinessException(ErrorCode.INVALID_INSTALLATION_ID);
        }
    }
}
