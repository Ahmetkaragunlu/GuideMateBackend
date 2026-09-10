package com.ahmetkaragunlu.guidematebackend.auth.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RegisterRequestValidationTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @ParameterizedTest
    @ValueSource(strings = {"José", "Anne-Marie", "O'Connor", "D'Arcy", "İlker Can", " José "})
    void acceptsInternationalFirstNames(String firstName) {
        Set<ConstraintViolation<RegisterRequest>> violations = validator.validate(request(firstName, "Li"));

        assertThat(violations).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"aa ", "a a", "a-", "a''a", "Anne  Marie"})
    void rejectsInvalidFirstNames(String firstName) {
        Set<ConstraintViolation<RegisterRequest>> violations = validator.validate(request(firstName, "Li"));

        assertThat(violations)
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("firstName");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Li", "O'Connor", " García "})
    void acceptsValidLastNames(String lastName) {
        Set<ConstraintViolation<RegisterRequest>> violations = validator.validate(request("Ada", lastName));

        assertThat(violations).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"A ", "A-", "A  B"})
    void rejectsInvalidLastNames(String lastName) {
        Set<ConstraintViolation<RegisterRequest>> violations = validator.validate(request("Ada", lastName));

        assertThat(violations)
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains("lastName");
    }

    private RegisterRequest request(String firstName, String lastName) {
        return new RegisterRequest(firstName, lastName, "user@example.com", "12345678");
    }
}
