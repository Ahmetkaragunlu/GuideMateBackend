package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class AuthRequestSizeValidationTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @ParameterizedTest
    @MethodSource("oversizedAuthRequests")
    void rejectsOversizedPublicAuthFields(Object request, String field) {
        assertThat(sizeViolations(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(field);
    }

    @Test
    void acceptsConfiguredBoundarySizes() {
        RegisterRequest request = new RegisterRequest(
                "A".repeat(100),
                "B".repeat(100),
                "a".repeat(64) + "@" + "b".repeat(251) + ".com",
                "p".repeat(64)
        );

        assertThat(sizeViolations(request)).isEmpty();
        assertThat(sizeViolations(new GoogleLoginRequest("t".repeat(8192)))).isEmpty();
        assertThat(sizeViolations(new RefreshTokenRequest("t".repeat(128)))).isEmpty();
        assertThat(sizeViolations(new ChangePasswordRequest("12345678", "p".repeat(64)))).isEmpty();
    }

    private static Stream<Arguments> oversizedAuthRequests() {
        String longEmail = "e".repeat(321);
        String longPassword = "p".repeat(65);
        String longToken = "t".repeat(129);
        return Stream.of(
                Arguments.of(new RegisterRequest("A".repeat(101), "Li", "a@b.co", "12345678"), "firstName"),
                Arguments.of(new RegisterRequest("Ada", "B".repeat(101), "a@b.co", "12345678"), "lastName"),
                Arguments.of(new RegisterRequest("Ada", "Li", longEmail, "12345678"), "email"),
                Arguments.of(new LoginRequest(longEmail, "12345678"), "email"),
                Arguments.of(new ForgotPasswordRequest(longEmail), "email"),
                Arguments.of(new ResendVerificationRequest(longEmail), "email"),
                Arguments.of(new RegisterRequest("Ada", "Li", "a@b.co", longPassword), "password"),
                Arguments.of(new LoginRequest("a@b.co", longPassword), "password"),
                Arguments.of(new ChangePasswordRequest(longPassword, "12345678"), "currentPassword"),
                Arguments.of(new ResetPasswordRequest(longToken, "12345678", "12345678"), "token"),
                Arguments.of(new RefreshTokenRequest(longToken), "token"),
                Arguments.of(new GoogleLoginRequest("g".repeat(8193)), "idToken")
        );
    }

    private Set<ConstraintViolation<Object>> sizeViolations(Object request) {
        return validator.validate(request).stream()
                .filter(violation -> "Size".equals(
                        violation.getConstraintDescriptor().getAnnotation().annotationType().getSimpleName()
                ))
                .collect(java.util.stream.Collectors.toSet());
    }
}
