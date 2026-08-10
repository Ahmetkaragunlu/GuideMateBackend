CREATE TABLE payment_provider_customers (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_customer_key_encrypted TEXT NOT NULL,
    provider_customer_key_fingerprint VARCHAR(64) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_payment_provider_customer_key
        UNIQUE (provider, provider_customer_key_fingerprint),
    CONSTRAINT chk_payment_provider_customer_provider
        CHECK (provider = 'IYZICO')
);

CREATE TABLE saved_payment_methods (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_card_token_encrypted TEXT NOT NULL,
    provider_card_token_fingerprint VARCHAR(64) NOT NULL,
    alias VARCHAR(100),
    bank_name VARCHAR(128),
    bank_code VARCHAR(16),
    card_family VARCHAR(64),
    card_association VARCHAR(32),
    card_type VARCHAR(32),
    last_four_digits VARCHAR(4) NOT NULL,
    card_holder_name VARCHAR(160),
    expiry_month SMALLINT,
    expiry_year SMALLINT,
    is_default BOOLEAN NOT NULL,
    default_guard BOOLEAN,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_saved_payment_method_token
        UNIQUE (provider, provider_card_token_fingerprint),
    CONSTRAINT uq_saved_payment_method_default
        UNIQUE (user_id, default_guard),
    CONSTRAINT chk_saved_payment_method_provider
        CHECK (provider = 'IYZICO'),
    CONSTRAINT chk_saved_payment_method_status
        CHECK (status IN ('ACTIVE', 'DELETED', 'EXPIRED')),
    CONSTRAINT chk_saved_payment_method_last_four
        CHECK (CHAR_LENGTH(last_four_digits) = 4),
    CONSTRAINT chk_saved_payment_method_expiry_month
        CHECK (expiry_month IS NULL OR expiry_month BETWEEN 1 AND 12),
    CONSTRAINT chk_saved_payment_method_expiry_year
        CHECK (expiry_year IS NULL OR expiry_year BETWEEN 2000 AND 9999),
    CONSTRAINT chk_saved_payment_method_default_guard
        CHECK (
            (is_default = TRUE AND status = 'ACTIVE' AND default_guard = TRUE)
            OR ((is_default = FALSE OR status <> 'ACTIVE') AND default_guard IS NULL)
        )
);

CREATE INDEX idx_saved_payment_method_user_status
    ON saved_payment_methods(user_id, status);
