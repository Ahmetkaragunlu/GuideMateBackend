package com.ahmetkaragunlu.guidematebackend.persistence;

import com.ahmetkaragunlu.guidematebackend.auth.security.SecureTokenService;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

class AuthTokenMigrationIntegrationTest {

    private static final String CONFIRMATION_RAW_TOKEN = "legacy-confirmation-token";
    private static final String RESET_RAW_TOKEN = "legacy-reset-token";
    private static final ZoneId LEGACY_ZONE = ZoneId.of("Europe/Istanbul");

    @Test
    void hashesExistingRawTokensAndPreservesTheirActualInstants() throws Exception {
        try (PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18-alpine")) {
            postgres.start();
            migrate(postgres, "17");

            LocalDateTime expiresAt = LocalDateTime.of(2026, 1, 15, 12, 30);
            LocalDateTime usedAt = LocalDateTime.of(2026, 1, 15, 11, 45);
            insertLegacyTokens(postgres, expiresAt, usedAt);

            migrate(postgres, null);

            SecureTokenService tokenService = new SecureTokenService();
            assertMigratedToken(
                    postgres,
                    "confirmation_tokens",
                    tokenService.hash(CONFIRMATION_RAW_TOKEN),
                    expiresAt.atZone(LEGACY_ZONE).toInstant(),
                    usedAt.atZone(LEGACY_ZONE).toInstant()
            );
            assertConfirmationTimestamp(
                    postgres,
                    usedAt.atZone(LEGACY_ZONE).toInstant()
            );
            assertMigratedToken(
                    postgres,
                    "password_reset_tokens",
                    tokenService.hash(RESET_RAW_TOKEN),
                    expiresAt.atZone(LEGACY_ZONE).toInstant(),
                    usedAt.atZone(LEGACY_ZONE).toInstant()
            );
        }
    }

    private void migrate(PostgreSQLContainer postgres, String target) {
        var configuration = Flyway.configure()
                .dataSource(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())
                .locations("classpath:db/migration");
        if (target != null) {
            configuration.target(target);
        }
        configuration.load().migrate();
    }

    private void insertLegacyTokens(
            PostgreSQLContainer postgres,
            LocalDateTime expiresAt,
            LocalDateTime usedAt
    ) throws Exception {
        try (Connection connection = connection(postgres)) {
            long userId;
            try (PreparedStatement statement = connection.prepareStatement(
                    """
                    INSERT INTO users (
                        first_name, last_name, email, password, role_selected,
                        account_status, token_version, created_at
                    ) VALUES (?, ?, ?, ?, false, 'PENDING_VERIFICATION', 0, ?)
                    RETURNING id
                    """
            )) {
                statement.setString(1, "Legacy");
                statement.setString(2, "User");
                statement.setString(3, "legacy@example.com");
                statement.setString(4, "not-used");
                statement.setObject(5, LocalDateTime.of(2026, 1, 1, 10, 0));
                try (ResultSet result = statement.executeQuery()) {
                    result.next();
                    userId = result.getLong(1);
                }
            }

            insertLegacyToken(connection, "confirmation_tokens", CONFIRMATION_RAW_TOKEN, userId, expiresAt, usedAt);
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE confirmation_tokens SET confirmed_at = ? WHERE user_id = ?"
            )) {
                statement.setObject(1, usedAt);
                statement.setLong(2, userId);
                statement.executeUpdate();
            }
            insertLegacyToken(connection, "password_reset_tokens", RESET_RAW_TOKEN, userId, expiresAt, usedAt);
        }
    }

    private void assertConfirmationTimestamp(
            PostgreSQLContainer postgres,
            Instant expectedConfirmedAt
    ) throws Exception {
        try (Connection connection = connection(postgres);
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT confirmed_at FROM confirmation_tokens"
             );
             ResultSet result = statement.executeQuery()) {
            assertThat(result.next()).isTrue();
            assertThat(result.getObject("confirmed_at", java.time.OffsetDateTime.class).toInstant())
                    .isEqualTo(expectedConfirmedAt);
        }
    }

    private void insertLegacyToken(
            Connection connection,
            String table,
            String rawToken,
            long userId,
            LocalDateTime expiresAt,
            LocalDateTime usedAt
    ) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO " + table + " (token, expires_at, used, used_at, user_id, created_at) "
                        + "VALUES (?, ?, true, ?, ?, ?)"
        )) {
            statement.setString(1, rawToken);
            statement.setObject(2, expiresAt);
            statement.setObject(3, usedAt);
            statement.setLong(4, userId);
            statement.setObject(5, LocalDateTime.of(2026, 1, 1, 10, 0));
            statement.executeUpdate();
        }
    }

    private void assertMigratedToken(
            PostgreSQLContainer postgres,
            String table,
            String expectedHash,
            Instant expectedExpiry,
            Instant expectedUsedAt
    ) throws Exception {
        try (Connection connection = connection(postgres);
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT token_hash, expires_at, used_at FROM " + table
             );
             ResultSet result = statement.executeQuery()) {
            assertThat(result.next()).isTrue();
            assertThat(result.getString("token_hash")).isEqualTo(expectedHash);
            assertThat(result.getObject("expires_at", java.time.OffsetDateTime.class).toInstant())
                    .isEqualTo(expectedExpiry);
            assertThat(result.getObject("used_at", java.time.OffsetDateTime.class).toInstant())
                    .isEqualTo(expectedUsedAt);
        }
    }

    private Connection connection(PostgreSQLContainer postgres) throws Exception {
        return DriverManager.getConnection(
                postgres.getJdbcUrl(),
                postgres.getUsername(),
                postgres.getPassword()
        );
    }
}
