package com.ahmetkaragunlu.guidematebackend.user.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AdminAccountSeedPropertiesTest {

    @Test
    void allowsMissingCredentialsWhenAdminSeedIsDisabled() {
        assertThatCode(() -> new AdminAccountSeedProperties(false, null, null, null, null))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsCompleteConfigurationWhenAdminSeedIsEnabled() {
        assertThatCode(() -> new AdminAccountSeedProperties(
                true,
                "admin@guidemate.test",
                "12345678",
                "GuideMate",
                "Admin"
        )).doesNotThrowAnyException();
    }

    @ParameterizedTest(name = "rejects missing {0}")
    @MethodSource("missingRequiredFields")
    void rejectsMissingRequiredConfigurationWhenAdminSeedIsEnabled(
            String environmentVariable,
            String email,
            String password,
            String firstName,
            String lastName
    ) {
        assertThatThrownBy(() -> new AdminAccountSeedProperties(
                true,
                email,
                password,
                firstName,
                lastName
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(environmentVariable + " is required when admin seed is enabled");
    }

    private static Stream<Arguments> missingRequiredFields() {
        return Stream.of(
                Arguments.of("ADMIN_EMAIL", " ", "12345678", "GuideMate", "Admin"),
                Arguments.of("ADMIN_PASSWORD", "admin@guidemate.test", null, "GuideMate", "Admin"),
                Arguments.of("ADMIN_FIRST_NAME", "admin@guidemate.test", "12345678", "", "Admin"),
                Arguments.of("ADMIN_LAST_NAME", "admin@guidemate.test", "12345678", "GuideMate", null)
        );
    }
}
