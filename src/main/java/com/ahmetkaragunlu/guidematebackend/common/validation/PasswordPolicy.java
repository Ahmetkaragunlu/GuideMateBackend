package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordPolicy {

    private static final Pattern NUMERIC_PASSWORD = Pattern.compile("^\\d{8,64}$");

    public void validate(String password) {
        if (password == null || !NUMERIC_PASSWORD.matcher(password).matches()) {
            throw new BusinessException(ErrorCode.PASSWORD_POLICY_VIOLATION);
        }
    }
}
