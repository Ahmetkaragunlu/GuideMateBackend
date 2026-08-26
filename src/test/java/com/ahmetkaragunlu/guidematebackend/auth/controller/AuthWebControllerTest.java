package com.ahmetkaragunlu.guidematebackend.auth.controller;

import com.ahmetkaragunlu.guidematebackend.auth.service.AccountVerificationService;
import com.ahmetkaragunlu.guidematebackend.auth.service.PasswordManagementService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.MessageSource;
import org.springframework.web.servlet.ModelAndView;

import java.util.Locale;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthWebControllerTest {

    private AccountVerificationService accountVerificationService;
    private PasswordManagementService passwordManagementService;
    private AuthWebController controller;

    @BeforeEach
    void setUp() {
        accountVerificationService = mock(AccountVerificationService.class);
        passwordManagementService = mock(PasswordManagementService.class);
        MessageSource messageSource = mock(MessageSource.class);
        when(messageSource.getMessage(anyString(), isNull(), any(Locale.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        controller = new AuthWebController(
                accountVerificationService,
                passwordManagementService,
                messageSource
        );
    }

    @Test
    void rendersSuccessfulConfirmation() {
        ModelAndView view = controller.confirmAccount("valid-token");

        assertView(view, "email-confirmation", "success", true);
        assertThat(view.getModel()).containsEntry("title", "web.confirm.success.title")
                .containsEntry("message", "web.confirm.success.message");
    }

    @ParameterizedTest
    @MethodSource("confirmationErrors")
    void rendersKnownConfirmationFailure(ErrorCode errorCode, String expectedTitle, String expectedMessage) {
        doThrow(new BusinessException(errorCode))
                .when(accountVerificationService)
                .confirmAccount("token");

        ModelAndView view = controller.confirmAccount("token");

        assertView(view, "email-confirmation", "success", false);
        assertThat(view.getModel()).containsEntry("title", expectedTitle)
                .containsEntry("message", expectedMessage);
    }

    @Test
    void propagatesUnexpectedConfirmationFailure() {
        doThrow(new BusinessException(ErrorCode.USER_NOT_FOUND))
                .when(accountVerificationService)
                .confirmAccount("token");

        assertThatThrownBy(() -> controller.confirmAccount("token"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND));
    }

    @Test
    void rendersResetFormForUsableToken() {
        ModelAndView view = controller.showResetPasswordForm("valid-token");

        assertView(view, "reset-password", "validToken", true);
        assertThat(view.getModel()).containsEntry("token", "valid-token")
                .containsEntry("title", "web.reset.title")
                .containsEntry("message", "web.reset.instructions");
    }

    @ParameterizedTest
    @MethodSource("resetErrors")
    void rendersKnownResetTokenFailure(ErrorCode errorCode, String expectedTitle, String expectedMessage) {
        doThrow(new BusinessException(errorCode))
                .when(passwordManagementService)
                .validateResetToken("token");

        ModelAndView view = controller.showResetPasswordForm("token");

        assertView(view, "reset-password", "validToken", false);
        assertThat(view.getModel()).containsEntry("title", expectedTitle)
                .containsEntry("message", expectedMessage)
                .doesNotContainKey("token");
    }

    @Test
    void propagatesUnexpectedResetTokenFailure() {
        doThrow(new BusinessException(ErrorCode.ACCOUNT_DISABLED))
                .when(passwordManagementService)
                .validateResetToken("token");

        assertThatThrownBy(() -> controller.showResetPasswordForm("token"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_DISABLED));
    }

    private void assertView(ModelAndView view, String viewName, String stateKey, boolean stateValue) {
        assertThat(view.getViewName()).isEqualTo(viewName);
        assertThat(view.getModel()).containsEntry(stateKey, stateValue);
    }

    private static Stream<Arguments> confirmationErrors() {
        return Stream.of(
                Arguments.of(
                        ErrorCode.TOKEN_EXPIRED,
                        "web.confirm.expired.title",
                        "web.confirm.expired.message"
                ),
                Arguments.of(
                        ErrorCode.TOKEN_ALREADY_USED,
                        "web.confirm.used.title",
                        "web.confirm.used.message"
                ),
                Arguments.of(
                        ErrorCode.INVALID_TOKEN,
                        "web.confirm.invalid.title",
                        "web.confirm.invalid.message"
                ),
                Arguments.of(
                        ErrorCode.ACCOUNT_DISABLED,
                        "web.confirm.disabled.title",
                        "web.confirm.disabled.message"
                )
        );
    }

    private static Stream<Arguments> resetErrors() {
        return Stream.of(
                Arguments.of(ErrorCode.TOKEN_EXPIRED, "web.reset.expired.title", "web.reset.expired.message"),
                Arguments.of(ErrorCode.TOKEN_ALREADY_USED, "web.reset.used.title", "web.reset.used.message"),
                Arguments.of(ErrorCode.INVALID_TOKEN, "web.reset.invalid.title", "web.reset.invalid.message")
        );
    }
}
