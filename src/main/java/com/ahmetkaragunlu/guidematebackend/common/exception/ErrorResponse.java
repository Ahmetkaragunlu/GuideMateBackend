package com.ahmetkaragunlu.guidematebackend.common.exception;


import java.time.LocalDateTime;

public record ErrorResponse(
        int code,
        String message,
        LocalDateTime timestamp
) {
    public ErrorResponse(int code, String message) {
        this(code, message, LocalDateTime.now());
    }
}