package com.ahmetkaragunlu.guidematebackend.common.exception;

import com.ahmetkaragunlu.guidematebackend.common.exception.response.ErrorResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.http.ResponseEntity;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;

    @BeforeEach
    void setUp() {
        MessageSource messageSource = mock(MessageSource.class);
        when(messageSource.getMessage(any(String.class), isNull(), any(Locale.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        handler = new GlobalExceptionHandler(messageSource);
    }

    @Test
    void rateLimitResponseIncludesRetryAfterAndStableCode() {
        ResponseEntity<ErrorResponse> response = handler.handleRateLimit(new RateLimitException(42));

        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("42");
        assertThat(response.getBody()).extracting(ErrorResponse::code).isEqualTo("RATE_LIMITED");
    }

    @Test
    void persistenceFailuresUseStablePublicCodes() {
        ResponseEntity<ErrorResponse> conflict = handler.handleDataConflict(
                new DataIntegrityViolationException("private database detail")
        );
        ResponseEntity<ErrorResponse> concurrent = handler.handleConcurrentUpdate(
                new ObjectOptimisticLockingFailureException(User.class, 1L)
        );
        ErrorResponse conflictBody = conflict.getBody();
        ErrorResponse concurrentBody = concurrent.getBody();

        Assertions.assertNotNull(conflictBody);
        Assertions.assertNotNull(concurrentBody);
        assertThat(conflictBody.code()).isEqualTo("DATA_CONFLICT");
        assertThat(concurrentBody.code()).isEqualTo("CONCURRENT_UPDATE");
        assertThat(conflictBody.message()).doesNotContain("private database detail");
    }

    @Test
    void unexpectedFailureDoesNotExposeTechnicalDetail() {
        ResponseEntity<ErrorResponse> response = handler.handleUnexpectedException(
                new IllegalStateException("database password leaked")
        );
        ErrorResponse body = response.getBody();

        Assertions.assertNotNull(body);
        assertThat(body.code()).isEqualTo("INTERNAL_SERVER_ERROR");
        assertThat(body.message()).doesNotContain("database password leaked");
    }
}
