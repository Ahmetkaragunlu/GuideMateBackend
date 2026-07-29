package com.ahmetkaragunlu.guidematebackend.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    USER_NOT_FOUND("error.user.notFound", HttpStatus.NOT_FOUND),
    EMAIL_ALREADY_EXISTS("error.email.alreadyExists", HttpStatus.CONFLICT),
    ACCOUNT_PENDING_VERIFICATION("error.account.pendingVerification", HttpStatus.FORBIDDEN),
    ACCOUNT_DISABLED("error.account.disabled", HttpStatus.FORBIDDEN),
    INVALID_CREDENTIALS("error.credentials.invalid", HttpStatus.UNAUTHORIZED),
    CURRENT_PASSWORD_INCORRECT("error.password.currentIncorrect", HttpStatus.BAD_REQUEST),
    PASSWORD_POLICY_VIOLATION("error.password.policy", HttpStatus.BAD_REQUEST),
    PASSWORD_SAME_AS_CURRENT("error.password.sameAsCurrent", HttpStatus.BAD_REQUEST),
    PASSWORDS_DO_NOT_MATCH("error.passwords.notMatch", HttpStatus.BAD_REQUEST),
    ROLE_ALREADY_SELECTED("error.role.alreadySelected", HttpStatus.CONFLICT),
    ROLE_NOT_FOUND("error.role.notFound", HttpStatus.NOT_FOUND),
    INVALID_INSTALLATION_ID("error.installation.invalid", HttpStatus.BAD_REQUEST),

    INVALID_TOKEN("error.token.invalid", HttpStatus.BAD_REQUEST),
    TOKEN_EXPIRED("error.token.expired", HttpStatus.BAD_REQUEST),
    TOKEN_ALREADY_USED("error.token.alreadyUsed", HttpStatus.BAD_REQUEST),
    INVALID_REFRESH_TOKEN("error.refreshToken.invalid", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_EXPIRED("error.refreshToken.expired", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REPLAY("error.refreshToken.replay", HttpStatus.UNAUTHORIZED),

    GOOGLE_LOGIN_FAILED("error.google.loginFailed", HttpStatus.UNAUTHORIZED),
    GOOGLE_ACCOUNT_NOT_FOUND("error.google.accountNotFound", HttpStatus.NOT_FOUND),
    GOOGLE_ACCOUNT_MISMATCH("error.google.accountMismatch", HttpStatus.CONFLICT),

    UNAUTHORIZED("error.security.unauthorized", HttpStatus.UNAUTHORIZED),
    FORBIDDEN("error.security.forbidden", HttpStatus.FORBIDDEN),
    VALIDATION_FAILED("error.validation.failed", HttpStatus.BAD_REQUEST),
    MALFORMED_REQUEST("error.request.malformed", HttpStatus.BAD_REQUEST),
    DATA_CONFLICT("error.data.conflict", HttpStatus.CONFLICT),
    RATE_LIMITED("error.rateLimit.exceeded", HttpStatus.TOO_MANY_REQUESTS),
    EMAIL_DELIVERY_FAILED("error.email.deliveryFailed", HttpStatus.SERVICE_UNAVAILABLE),
    INTERNAL_SERVER_ERROR("error.server.internal", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String messageKey;
    private final HttpStatus httpStatus;

    ErrorCode(String messageKey, HttpStatus httpStatus) {
        this.messageKey = messageKey;
        this.httpStatus = httpStatus;
    }
}
