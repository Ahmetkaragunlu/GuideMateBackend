package com.ahmetkaragunlu.guidematebackend.common;

import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

class MessageBundleContractTest {

    @Test
    void definesNonBlankMessageForEveryPublicErrorCode() throws IOException {
        Properties messages = new Properties();
        try (InputStream input = getClass().getResourceAsStream("/messages.properties")) {
            assertThat(input).as("messages.properties must be on the runtime classpath").isNotNull();
            messages.load(input);
        }

        assertThat(Arrays.stream(ErrorCode.values()).map(ErrorCode::getMessageKey))
                .allSatisfy(messageKey -> {
                    assertThat(messages).containsKey(messageKey);
                    assertThat(messages.getProperty(messageKey)).isNotBlank();
                });
    }
}
