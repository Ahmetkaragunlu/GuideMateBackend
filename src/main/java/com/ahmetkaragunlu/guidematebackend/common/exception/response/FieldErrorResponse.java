package com.ahmetkaragunlu.guidematebackend.common.exception.response;

public record FieldErrorResponse(
        String field,
        String code,
        String message
) {
}
