package com.ahmetkaragunlu.guidematebackend.common.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final MessageSource messageSource;

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorResponse> handleBusinessException(BusinessException ex) {
        String message = messageSource.getMessage(
                ex.getErrorCode().getMessageKey(),
                null,
                LocaleContextHolder.getLocale()
        );

        ErrorResponse response = new ErrorResponse(
                ex.getErrorCode().getCode(),
                message
        );
        return ResponseEntity
                .status(ex.getErrorCode().getHttpStatus())
                .body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException() {
        String message = messageSource.getMessage(
                ErrorCode.INVALID_CREDENTIALS.getMessageKey(),
                null,
                LocaleContextHolder.getLocale()
        );

        ErrorResponse response = new ErrorResponse(
                ErrorCode.INVALID_CREDENTIALS.getCode(),
                message
        );
        return ResponseEntity
                .status(ErrorCode.INVALID_CREDENTIALS.getHttpStatus())
                .body(response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return ResponseEntity.badRequest().body(errors);
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex) {
        String message = messageSource.getMessage(
                "error.server.unexpected",
                null,
                LocaleContextHolder.getLocale()
        );

        ErrorResponse response = new ErrorResponse(
                ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                message + ex.getMessage()
        );
        return ResponseEntity
                .status(ErrorCode.INTERNAL_SERVER_ERROR.getHttpStatus())
                .body(response);
    }

    @ExceptionHandler({DisabledException.class, LockedException.class})
    public ResponseEntity<ErrorResponse> handleDisabledException() {
        String message = messageSource.getMessage(
                ErrorCode.ACCOUNT_NOT_ACTIVE.getMessageKey(),
                null,
                LocaleContextHolder.getLocale()
        );

        ErrorResponse response = new ErrorResponse(
                ErrorCode.ACCOUNT_NOT_ACTIVE.getCode(),
                message
        );

        return ResponseEntity
                .status(ErrorCode.ACCOUNT_NOT_ACTIVE.getHttpStatus())
                .body(response);
    }
}