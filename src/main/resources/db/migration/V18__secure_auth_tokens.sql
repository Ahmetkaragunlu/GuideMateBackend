UPDATE confirmation_tokens
SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex');

UPDATE password_reset_tokens
SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex');

ALTER TABLE confirmation_tokens
    RENAME COLUMN token TO token_hash;

ALTER TABLE password_reset_tokens
    RENAME COLUMN token TO token_hash;

ALTER TABLE confirmation_tokens
    RENAME CONSTRAINT confirmation_tokens_token_key TO confirmation_tokens_token_hash_key;

ALTER TABLE password_reset_tokens
    RENAME CONSTRAINT password_reset_tokens_token_key TO password_reset_tokens_token_hash_key;

ALTER TABLE confirmation_tokens
    ALTER COLUMN expires_at TYPE TIMESTAMP(6) WITH TIME ZONE
        USING expires_at AT TIME ZONE 'Europe/Istanbul',
    ALTER COLUMN used_at TYPE TIMESTAMP(6) WITH TIME ZONE
        USING used_at AT TIME ZONE 'Europe/Istanbul',
    ALTER COLUMN confirmed_at TYPE TIMESTAMP(6) WITH TIME ZONE
        USING confirmed_at AT TIME ZONE 'Europe/Istanbul';

ALTER TABLE password_reset_tokens
    ALTER COLUMN expires_at TYPE TIMESTAMP(6) WITH TIME ZONE
        USING expires_at AT TIME ZONE 'Europe/Istanbul',
    ALTER COLUMN used_at TYPE TIMESTAMP(6) WITH TIME ZONE
        USING used_at AT TIME ZONE 'Europe/Istanbul';
