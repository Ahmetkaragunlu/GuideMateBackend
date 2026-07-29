package com.ahmetkaragunlu.guidematebackend.common.exception;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final MessageSource messageSource;

    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<ErrorResponse> handleRateLimit(RateLimitException exception) {
        return ResponseEntity
                .status(ErrorCode.RATE_LIMITED.getHttpStatus())
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(exception.getRetryAfterSeconds()))
                .body(response(ErrorCode.RATE_LIMITED));
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorResponse> handleBusinessException(BusinessException exception) {
        ErrorCode errorCode = exception.getErrorCode();
        return ResponseEntity
                .status(errorCode.getHttpStatus())
                .body(response(errorCode));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException exception) {
        List<FieldErrorResponse> fieldErrors = exception.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(this::toFieldError)
                .toList();

        String message = message(ErrorCode.VALIDATION_FAILED);
        return ResponseEntity
                .badRequest()
                .body(ErrorResponse.validation(message, fieldErrors));
    }

    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            ServletRequestBindingException.class
    })
    public ResponseEntity<ErrorResponse> handleMalformedRequest(Exception exception) {
        return ResponseEntity
                .badRequest()
                .body(response(ErrorCode.MALFORMED_REQUEST));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException exception) {
        return ResponseEntity
                .status(ErrorCode.UNAUTHORIZED.getHttpStatus())
                .body(response(ErrorCode.UNAUTHORIZED));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException exception) {
        return ResponseEntity
                .status(ErrorCode.FORBIDDEN.getHttpStatus())
                .body(response(ErrorCode.FORBIDDEN));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataConflict(DataIntegrityViolationException exception) {
        return ResponseEntity
                .status(ErrorCode.DATA_CONFLICT.getHttpStatus())
                .body(response(ErrorCode.DATA_CONFLICT));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpectedException(Exception exception) {
        log.error("Unexpected server error of type {}", exception.getClass().getName(), exception);
        return ResponseEntity
                .status(ErrorCode.INTERNAL_SERVER_ERROR.getHttpStatus())
                .body(response(ErrorCode.INTERNAL_SERVER_ERROR));
    }

    private ErrorResponse response(ErrorCode errorCode) {
        return ErrorResponse.of(errorCode, message(errorCode));
    }

    private String message(ErrorCode errorCode) {
        return messageSource.getMessage(
                errorCode.getMessageKey(),
                null,
                LocaleContextHolder.getLocale()
        );
    }

    private FieldErrorResponse toFieldError(FieldError fieldError) {
        return new FieldErrorResponse(
                fieldError.getField(),
                validationCode(fieldError.getCode()),
                fieldError.getDefaultMessage()
        );
    }

    private String validationCode(String springCode) {
        return switch (springCode == null ? "" : springCode) {
            case "NotBlank", "NotNull" -> "FIELD_REQUIRED";
            case "Email" -> "INVALID_EMAIL";
            case "Size" -> "INVALID_SIZE";
            case "Pattern" -> "INVALID_FORMAT";
            default -> "INVALID_FIELD";
        };
    }
}
