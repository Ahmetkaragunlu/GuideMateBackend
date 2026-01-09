package com.ahmetkaragunlu.guidematebackend.common.exception;


import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    // 1000: User & Auth Errors
    USER_NOT_FOUND(1001, "error.user.notFound", HttpStatus.NOT_FOUND),
    EMAIL_ALREADY_EXISTS(1002, "error.email.alreadyExists", HttpStatus.CONFLICT),
    ACCOUNT_NOT_ACTIVE(1003, "error.account.notActive", HttpStatus.FORBIDDEN),
    INVALID_CREDENTIALS(1004, "error.credentials.invalid", HttpStatus.UNAUTHORIZED),
    PASSWORDS_DO_NOT_MATCH(1005, "error.passwords.notMatch", HttpStatus.BAD_REQUEST),
    ROLE_ALREADY_SELECTED(1006, "error.role.alreadySelected", HttpStatus.BAD_REQUEST),
    ROLE_NOT_FOUND(1007, "error.role.notFound", HttpStatus.NOT_FOUND),

    // 2000: Token Errors
    INVALID_TOKEN(2001, "error.token.invalid", HttpStatus.BAD_REQUEST),
    TOKEN_EXPIRED(2002, "error.token.expired", HttpStatus.UNAUTHORIZED),
    TOKEN_ALREADY_USED(2003, "error.token.alreadyUsed", HttpStatus.BAD_REQUEST),

    // 3000: Google & 3rd Party
    GOOGLE_LOGIN_FAILED(3001, "error.google.loginFailed", HttpStatus.UNAUTHORIZED),

    // 9000: System
    INTERNAL_SERVER_ERROR(9000, "error.server.internal", HttpStatus.INTERNAL_SERVER_ERROR);

    private final int code;
    private final String messageKey;
    private final HttpStatus httpStatus;

    ErrorCode(int code, String messageKey, HttpStatus httpStatus) {
        this.code = code;
        this.messageKey = messageKey;
        this.httpStatus = httpStatus;
    }
}