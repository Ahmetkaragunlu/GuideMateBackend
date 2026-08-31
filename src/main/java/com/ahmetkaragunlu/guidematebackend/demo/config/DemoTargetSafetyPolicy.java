package com.ahmetkaragunlu.guidematebackend.demo.config;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;

final class DemoTargetSafetyPolicy {

    static final String DEMO_PROFILE = "demo";
    static final String EXPECTED_DATABASE_NAME = "guidemate_demo";
    static final String DEMO_MEDIA_DIRECTORY_NAME = "guidemate-demo-media";

    private static final Set<String> FORBIDDEN_PROFILES = Set.of("local", "prod");

    private DemoTargetSafetyPolicy() {
    }

    static void requireSafeTargets(
            String[] activeProfiles,
            String datasourceUrl,
            String mediaStorageRoot
    ) {
        Set<String> profiles = Set.copyOf(Arrays.asList(activeProfiles));
        if (!profiles.contains(DEMO_PROFILE) || profiles.stream().anyMatch(FORBIDDEN_PROFILES::contains)) {
            throw new IllegalStateException("Demo operations require the isolated demo profile");
        }

        if (!EXPECTED_DATABASE_NAME.equals(databaseName(datasourceUrl))) {
            throw new IllegalStateException("Demo profile must target the guidemate_demo database");
        }

        Path expectedMediaRoot = Path.of(
                System.getProperty("user.home"),
                ".guidemate",
                DEMO_MEDIA_DIRECTORY_NAME
        ).toAbsolutePath().normalize();
        Path configuredMediaRoot = path(mediaStorageRoot);
        if (!expectedMediaRoot.equals(configuredMediaRoot)
                || Files.isSymbolicLink(expectedMediaRoot)
                || Files.isSymbolicLink(expectedMediaRoot.getParent())) {
            throw new IllegalStateException("Demo profile must target the isolated demo media root");
        }
    }

    private static String databaseName(String datasourceUrl) {
        if (datasourceUrl == null || !datasourceUrl.startsWith("jdbc:postgresql://")) {
            return null;
        }
        try {
            URI uri = URI.create(datasourceUrl.substring("jdbc:".length()));
            String path = uri.getPath();
            if (!"postgresql".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null
                    || path == null
                    || path.length() <= 1
                    || path.indexOf('/', 1) >= 0) {
                return null;
            }
            return path.substring(1);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static Path path(String value) {
        if (value == null || value.isBlank()) {
            return Path.of("").toAbsolutePath().normalize();
        }
        return Path.of(value).toAbsolutePath().normalize();
    }
}
