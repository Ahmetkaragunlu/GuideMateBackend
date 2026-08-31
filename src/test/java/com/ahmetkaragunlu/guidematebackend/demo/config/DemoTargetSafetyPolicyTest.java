package com.ahmetkaragunlu.guidematebackend.demo.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DemoTargetSafetyPolicyTest {

    private static final String DEMO_DATABASE_URL =
            "jdbc:postgresql://localhost:5432/guidemate_demo";

    @Test
    void acceptsOnlyTheIsolatedDemoTargets() {
        assertThatCode(() -> DemoTargetSafetyPolicy.requireSafeTargets(
                new String[]{"demo"},
                DEMO_DATABASE_URL,
                expectedMediaRoot()
        )).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"guidemate_db", "postgres", "guidemate_demo_backup"})
    void rejectsAnyDatabaseOtherThanTheExactDemoDatabase(String databaseName) {
        assertThatThrownBy(() -> DemoTargetSafetyPolicy.requireSafeTargets(
                new String[]{"demo"},
                "jdbc:postgresql://localhost:5432/" + databaseName,
                expectedMediaRoot()
        )).isInstanceOf(IllegalStateException.class)
                .hasMessage("Demo profile must target the guidemate_demo database");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:h2:mem:guidemate_demo",
            "jdbc:postgresql:guidemate_demo",
            "jdbc:postgresql://localhost:5432/guidemate_demo/extra",
            "not-a-jdbc-url"
    })
    void rejectsMalformedOrUnsupportedDatabaseUrls(String datasourceUrl) {
        assertThatThrownBy(() -> DemoTargetSafetyPolicy.requireSafeTargets(
                new String[]{"demo"},
                datasourceUrl,
                expectedMediaRoot()
        )).isInstanceOf(IllegalStateException.class)
                .hasMessage("Demo profile must target the guidemate_demo database");
    }

    @ParameterizedTest
    @ValueSource(strings = {"local", "prod"})
    void rejectsLocalOrProductionProfileCombinations(String forbiddenProfile) {
        assertThatThrownBy(() -> DemoTargetSafetyPolicy.requireSafeTargets(
                new String[]{"demo", forbiddenProfile},
                DEMO_DATABASE_URL,
                expectedMediaRoot()
        )).isInstanceOf(IllegalStateException.class)
                .hasMessage("Demo operations require the isolated demo profile");
    }

    @Test
    void rejectsTheNormalOrAnyOtherMediaRoot() {
        assertThatThrownBy(() -> DemoTargetSafetyPolicy.requireSafeTargets(
                new String[]{"demo"},
                DEMO_DATABASE_URL,
                Path.of(System.getProperty("user.home"), "guidemate-media").toString()
        )).isInstanceOf(IllegalStateException.class)
                .hasMessage("Demo profile must target the isolated demo media root");
    }

    private String expectedMediaRoot() {
        return Path.of(
                System.getProperty("user.home"),
                ".guidemate",
                DemoTargetSafetyPolicy.DEMO_MEDIA_DIRECTORY_NAME
        ).toString();
    }
}
