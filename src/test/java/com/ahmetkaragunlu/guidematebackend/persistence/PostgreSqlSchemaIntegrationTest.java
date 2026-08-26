package com.ahmetkaragunlu.guidematebackend.persistence;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class PostgreSqlSchemaIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void appliesAllMigrationsWithPostgreSqlSpecificSchemaFeatures() {
        String databaseVersion = jdbcTemplate.queryForObject("SELECT version()", String.class);
        Integer migrationCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history WHERE success",
                Integer.class
        );
        Integer failedMigrationCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history WHERE NOT success",
                Integer.class
        );
        String reservationSnapshotType = columnType("reservations", "purchase_snapshot");
        String notificationPayloadType = columnType("notifications", "payload");
        String reservationCreatedAtType = columnType("reservations", "created_at");
        Integer criticalConstraintCount = jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM pg_constraint
                WHERE conname IN (
                    'uq_reservation_active',
                    'uq_reservation_booking_idempotency',
                    'uq_payment_idempotency',
                    'uq_wallet_ledger_idempotency',
                    'uq_chat_message_client_id'
                )
                """,
                Integer.class
        );

        assertThat(databaseVersion).startsWith("PostgreSQL 18.");
        assertThat(migrationCount).isPositive();
        assertThat(failedMigrationCount).isZero();
        assertThat(reservationSnapshotType).isEqualTo("jsonb");
        assertThat(notificationPayloadType).isEqualTo("jsonb");
        assertThat(reservationCreatedAtType).isEqualTo("timestamp with time zone");
        assertThat(criticalConstraintCount).isEqualTo(5);
    }

    private String columnType(String tableName, String columnName) {
        return jdbcTemplate.queryForObject(
                """
                SELECT data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = ?
                  AND column_name = ?
                """,
                String.class,
                tableName,
                columnName
        );
    }
}
