package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.stereotype.Component;

import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.List;

@Component
class DemoDatasetWriter {

    private static final ClassPathResource SEED_SCRIPT =
            new ClassPathResource("demo/seed-dataset.sql");

    private final JdbcTemplate jdbcTemplate;

    DemoDatasetWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    void write(
            String passwordHash,
            Instant referenceInstant,
            List<DemoFixtureData.Media> mediaFixtures,
            List<DemoFixtureData.BankAccount> bankFixtures
    ) {
        configureSession(passwordHash, referenceInstant);
        createTemporaryTables();
        insertMediaFixtures(mediaFixtures);
        insertBankFixtures(bankFixtures);
        jdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            ScriptUtils.executeSqlScript(connection, SEED_SCRIPT);
            return null;
        });
    }

    private void configureSession(String passwordHash, Instant referenceInstant) {
        jdbcTemplate.queryForObject(
                "select set_config('guidemate.demo_password_hash', ?, true)",
                String.class,
                passwordHash
        );
        jdbcTemplate.queryForObject(
                "select set_config('guidemate.demo_reference_instant', ?, true)",
                String.class,
                referenceInstant.toString()
        );
        jdbcTemplate.execute("""
                create or replace function pg_temp.demo_uuid(seed text)
                returns uuid
                language sql
                immutable
                strict
                as 'with digest as (select md5(''guidemate-demo-v1:'' || seed) value)
                    select (
                        substr(value, 1, 8) || ''-'' || substr(value, 9, 4)
                        || ''-3'' || substr(value, 14, 3) || ''-''
                        || substr(
                            ''89ab'',
                            ((get_byte(decode(value, ''hex''), 8) >> 4) & 3) + 1,
                            1
                        )
                        || substr(value, 18, 3) || ''-'' || substr(value, 21, 12)
                    )::uuid
                    from digest'
                """);
    }

    private void createTemporaryTables() {
        jdbcTemplate.execute("""
                create temporary table demo_media_fixture (
                    id uuid primary key,
                    owner_id bigint not null,
                    purpose varchar(32) not null,
                    storage_key varchar(255) not null unique,
                    original_file_name varchar(255) not null,
                    content_type varchar(64) not null,
                    size_bytes bigint not null
                ) on commit drop
                """);
        jdbcTemplate.execute("""
                create temporary table demo_bank_fixture (
                    id uuid primary key,
                    guide_id bigint not null,
                    ordinal integer not null,
                    iban_encrypted text not null,
                    iban_fingerprint varchar(64) not null,
                    masked_iban varchar(34) not null,
                    bank_code varchar(8) not null,
                    bank_name varchar(128) not null,
                    account_holder_name varchar(160) not null
                ) on commit drop
                """);
    }

    private void insertMediaFixtures(List<DemoFixtureData.Media> fixtures) {
        jdbcTemplate.batchUpdate(
                """
                        insert into demo_media_fixture (
                            id, owner_id, purpose, storage_key, original_file_name,
                            content_type, size_bytes
                        ) values (?, ?, ?, ?, ?, ?, ?)
                        """,
                fixtures,
                fixtures.size(),
                this::bindMedia
        );
    }

    private void bindMedia(PreparedStatement statement, DemoFixtureData.Media fixture) throws java.sql.SQLException {
        statement.setObject(1, fixture.id());
        statement.setLong(2, fixture.ownerId());
        statement.setString(3, fixture.purpose());
        statement.setString(4, fixture.storageKey());
        statement.setString(5, fixture.originalFileName());
        statement.setString(6, fixture.contentType());
        statement.setLong(7, fixture.sizeBytes());
    }

    private void insertBankFixtures(List<DemoFixtureData.BankAccount> fixtures) {
        jdbcTemplate.batchUpdate(
                """
                        insert into demo_bank_fixture (
                            id, guide_id, ordinal, iban_encrypted, iban_fingerprint,
                            masked_iban, bank_code, bank_name, account_holder_name
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fixtures,
                fixtures.size(),
                this::bindBankAccount
        );
    }

    private void bindBankAccount(
            PreparedStatement statement,
            DemoFixtureData.BankAccount fixture
    ) throws java.sql.SQLException {
        statement.setObject(1, fixture.id());
        statement.setLong(2, fixture.guideId());
        statement.setInt(3, fixture.ordinal());
        statement.setString(4, fixture.ibanEncrypted());
        statement.setString(5, fixture.ibanFingerprint());
        statement.setString(6, fixture.maskedIban());
        statement.setString(7, fixture.bankCode());
        statement.setString(8, fixture.bankName());
        statement.setString(9, fixture.accountHolderName());
    }
}
