package com.ahmetkaragunlu.guidematebackend.user.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AccountStatusPolicyTest {

    private final AccountStatusPolicy policy = new AccountStatusPolicy();

    @Test
    void allowsActiveAccount() {
        User user = userWithStatus(AccountStatus.ACTIVE);

        assertThat(policy.accessError(user)).isEmpty();
        assertThatCode(() -> policy.requireActive(user)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @MethodSource("inaccessibleAccountStatuses")
    void mapsInactiveAccountToStableError(AccountStatus status, ErrorCode expectedError) {
        User user = userWithStatus(status);

        assertThat(policy.accessError(user)).contains(expectedError);
        assertThatThrownBy(() -> policy.requireActive(user))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(expectedError));
    }

    private static Stream<Arguments> inaccessibleAccountStatuses() {
        return Stream.of(
                Arguments.of(AccountStatus.PENDING_VERIFICATION, ErrorCode.ACCOUNT_PENDING_VERIFICATION),
                Arguments.of(AccountStatus.DISABLED, ErrorCode.ACCOUNT_DISABLED)
        );
    }

    private User userWithStatus(AccountStatus status) {
        User user = new User();
        user.setAccountStatus(status);
        return user;
    }
}
