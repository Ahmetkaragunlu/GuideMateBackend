package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.config.AppProperties;
import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.MessageSource;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.Locale;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SmtpEmailServiceTest {

    private JavaMailSender mailSender;
    private SmtpEmailService service;

    @BeforeEach
    void setUp() {
        mailSender = mock(JavaMailSender.class);
        MessageSource messageSource = mock(MessageSource.class);
        when(messageSource.getMessage(anyString(), nullable(Object[].class), any(Locale.class)))
                .thenAnswer(invocation -> {
                    Object[] arguments = invocation.getArgument(1);
                    return arguments == null || arguments.length == 0
                            ? invocation.getArgument(0)
                            : invocation.getArgument(0) + ":" + arguments[0];
                });
        service = new SmtpEmailService(
                mailSender,
                messageSource,
                "noreply@guidemate.test",
                new AppProperties(URI.create("https://api.guidemate.test/"))
        );
    }

    @Test
    void sendsConfirmationWithEncodedTokenAndNormalizedBaseUrl() {
        service.sendConfirmationEmail("user@example.com", "token_value-123");

        ArgumentCaptor<SimpleMailMessage> message = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(message.capture());
        assertThat(message.getValue().getFrom()).isEqualTo("noreply@guidemate.test");
        assertThat(message.getValue().getTo()).containsExactly("user@example.com");
        assertThat(message.getValue().getText())
                .contains("https://api.guidemate.test/api/v1/auth/confirm")
                .contains("token=token_value-123");
    }

    @Test
    void mapsMailProviderFailureToStableDomainException() {
        doThrow(new MailSendException("smtp unavailable"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        assertThatThrownBy(() -> service.sendPasswordResetEmail("user@example.com", "token"))
                .isInstanceOf(EmailDeliveryException.class);
    }
}
