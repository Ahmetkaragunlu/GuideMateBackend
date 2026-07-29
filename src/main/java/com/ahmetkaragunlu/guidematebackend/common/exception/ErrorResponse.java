package com.ahmetkaragunlu.guidematebackend.common.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

public record ErrorResponse(
        String code,
        String message,
        Instant timestamp,
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        List<FieldErrorResponse> fieldErrors
) {

    public static ErrorResponse of(ErrorCode errorCode, String message) {
        return new ErrorResponse(errorCode.name(), message, Instant.now(), List.of());
    }

    public static ErrorResponse validation(String message, List<FieldErrorResponse> fieldErrors) {
        return new ErrorResponse(
                ErrorCode.VALIDATION_FAILED.name(),
                message,
                Instant.now(),
                fieldErrors
        );
    }
}
