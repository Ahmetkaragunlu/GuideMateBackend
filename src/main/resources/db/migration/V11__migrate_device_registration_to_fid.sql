ALTER TABLE device_tokens RENAME TO device_registrations;
ALTER TABLE device_registrations RENAME COLUMN fcm_token TO firebase_installation_id;
ALTER TABLE device_registrations
    ALTER COLUMN firebase_installation_id SET DATA TYPE VARCHAR(128);

ALTER TABLE device_registrations
    RENAME CONSTRAINT uq_device_token_installation TO uq_device_registration_installation;
ALTER TABLE device_registrations
    RENAME CONSTRAINT uq_device_token_value TO uq_device_registration_firebase_installation;
ALTER TABLE device_registrations
    RENAME CONSTRAINT chk_device_token_platform TO chk_device_registration_platform;

ALTER INDEX idx_device_token_user_active RENAME TO idx_device_registration_user_active;
