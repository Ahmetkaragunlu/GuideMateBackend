package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.EmailDeliveryException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final MessageSource messageSource;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.public-base-url}")
    private String publicBaseUrl;

    private String getMessage(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Override
    public void sendConfirmationEmail(String to, String token) {
        try {
            String confirmationUrl = buildUrl("/api/v1/auth/confirm", token);
            String subject = getMessage("email.confirmation.subject");
            String body = getMessage("email.confirmation.body", confirmationUrl);

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
        } catch (MailException exception) {
            log.error("Confirmation email delivery failed: {}", exception.getClass().getSimpleName());
            throw new EmailDeliveryException(exception);
        }
    }

    @Override
    public void sendPasswordResetEmail(String to, String token) {
        try {
            String resetUrl = buildUrl("/api/v1/auth/reset-password-form", token);
            String subject = getMessage("email.passwordReset.subject");
            String body = getMessage("email.passwordReset.body", resetUrl);

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
        } catch (MailException exception) {
            log.error("Password reset email delivery failed: {}", exception.getClass().getSimpleName());
            throw new EmailDeliveryException(exception);
        }
    }

    private String buildUrl(String path, String token) {
        String normalizedBaseUrl = publicBaseUrl.endsWith("/")
                ? publicBaseUrl.substring(0, publicBaseUrl.length() - 1)
                : publicBaseUrl;
        return UriComponentsBuilder
                .fromUriString(normalizedBaseUrl)
                .path(path)
                .queryParam("token", token)
                .build()
                .encode()
                .toUriString();
    }
}
