package com.ahmetkaragunlu.guidematebackend.common.exception;

import lombok.Getter;

@Getter
public class RateLimitException extends BusinessException {

    private final long retryAfterSeconds;

    public RateLimitException(long retryAfterSeconds) {
        super(ErrorCode.RATE_LIMITED);
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }
}
