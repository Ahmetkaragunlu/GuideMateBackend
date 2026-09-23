package com.ahmetkaragunlu.guidematebackend.common;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OperationalLoggingContractTest {

    @Test
    void productionSourcesDoNotWriteDirectlyToConsole() throws IOException {
        Path sourceRoot = Path.of("src/main/java");
        try (var paths = Files.walk(sourceRoot)) {
            List<Path> offenders = paths
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(this::containsDirectConsoleOutput)
                    .toList();

            assertThat(offenders).isEmpty();
        }
    }

    private boolean containsDirectConsoleOutput(Path path) {
        try {
            String source = Files.readString(path);
            return source.contains("System.out")
                    || source.contains("System.err")
                    || source.contains("printStackTrace(");
        } catch (IOException exception) {
            throw new IllegalStateException("Could not inspect production source " + path, exception);
        }
    }
}
