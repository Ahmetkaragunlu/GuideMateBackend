package com.ahmetkaragunlu.guidematebackend.common.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AppPropertiesTest {

    @Test
    void normalizesTrailingSlashesWithoutChangingTheUrl() {
        AppProperties properties = new AppProperties(URI.create("https://api.guidemate.test///"));

        assertThat(properties.publicBaseUrl()).isEqualTo(URI.create("https://api.guidemate.test"));
    }

    @Test
    void acceptsHttpForLocalDevelopment() {
        AppProperties properties = new AppProperties(URI.create("http://192.168.1.10:8080"));

        assertThat(properties.publicBaseUrl()).isEqualTo(URI.create("http://192.168.1.10:8080"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/relative-path",
            "ftp://api.guidemate.test",
            "https:///missing-host"
    })
    void rejectsUrlsThatCannotBeUsedAsApplicationBaseUrl(String value) {
        assertThatThrownBy(() -> new AppProperties(URI.create(value)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute HTTP(S) URL");
    }
}
