package com.ahmetkaragunlu.guidematebackend.common.exception;

public record FieldErrorResponse(
        String field,
        String code,
        String message
) {
}
