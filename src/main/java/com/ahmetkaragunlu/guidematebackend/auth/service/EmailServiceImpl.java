package com.ahmetkaragunlu.guidematebackend.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final MessageSource messageSource;

    @Value("${spring.mail.username}")
    private String fromEmail;

    private String getMessage(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Async
    @Override
    public void sendConfirmationEmail(String to, String token) {
        try {
            String confirmationUrl = "http://localhost:8080/api/v1/auth/confirm?token=" + token;
            String subject = getMessage("email.confirmation.subject");
            String body = getMessage("email.confirmation.body", confirmationUrl);

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
            log.info("Confirmation email sent to: {}", to);
        } catch (Exception e) {
            log.error("Error sending confirmation email: ", e);
        }
    }

    @Async
    @Override
    public void sendPasswordResetEmail(String to, String token) {
        try {
            String subject = getMessage("email.passwordReset.subject");
            String body = getMessage("email.passwordReset.body", token);

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (Exception e) {
            log.error("Error sending password reset email: ", e);
        }
    }
}