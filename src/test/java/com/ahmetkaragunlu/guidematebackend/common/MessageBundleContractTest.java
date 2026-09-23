package com.ahmetkaragunlu.guidematebackend.common;

import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.profile.dto.UpdateUserAvatarRequest;
import com.ahmetkaragunlu.guidematebackend.review.dto.CreateReviewRequest;
import jakarta.validation.ConstraintViolation;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MessageBundleContractTest {

    @Test
    void definesNonBlankMessageForEveryPublicErrorCode() throws IOException {
        Properties messages = loadMessages();

        assertThat(Arrays.stream(ErrorCode.values()).map(ErrorCode::getMessageKey))
                .allSatisfy(messageKey -> {
                    assertThat(messages).containsKey(messageKey);
                    assertThat(messages.getProperty(messageKey)).isNotBlank();
                });
    }

    @Test
    void keepsUserAndValidationMessagesInSingleNonBlankBundle() throws IOException {
        Properties messages = loadMessages();

        assertThat(getClass().getResource("/ValidationMessages.properties")).isNull();
        assertNonBlankGroup(messages, "auth.");
        assertNonBlankGroup(messages, "email.");
        assertNonBlankGroup(messages, "web.");
        assertNonBlankGroup(messages, "validation.");
    }

    @Test
    void resolvesValidationFallbackFromTurkishApplicationBundle() {
        LocalValidatorFactoryBean validator = createValidator();

        Set<ConstraintViolation<UpdateUserAvatarRequest>> violations =
                validator.validate(new UpdateUserAvatarRequest(null));

        assertThat(violations)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("Profil foto\u011Fraf\u0131 se\u00E7ilmelidir");
        validator.close();
    }

    @Test
    void resolvesConstraintAttributesFromCentralValidationMessages() {
        LocalValidatorFactoryBean validator = createValidator();

        Set<ConstraintViolation<CreateReviewRequest>> violations =
                validator.validate(new CreateReviewRequest(6, null));

        assertThat(violations)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("Puan en fazla 5 olmal\u0131d\u0131r");
        validator.close();
    }

    private LocalValidatorFactoryBean createValidator() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setAlwaysUseMessageFormat(true);
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.setValidationMessageSource(messageSource);
        validator.afterPropertiesSet();
        return validator;
    }

    private Properties loadMessages() throws IOException {
        Properties messages = new Properties();
        try (InputStream input = getClass().getResourceAsStream("/messages.properties")) {
            assertThat(input).as("messages.properties must be on the runtime classpath").isNotNull();
            messages.load(input);
        }
        return messages;
    }

    private void assertNonBlankGroup(Properties messages, String prefix) {
        assertThat(messages.stringPropertyNames())
                .filteredOn(key -> key.startsWith(prefix))
                .isNotEmpty()
                .allSatisfy(key -> assertThat(messages.getProperty(key)).isNotBlank());
    }
}
