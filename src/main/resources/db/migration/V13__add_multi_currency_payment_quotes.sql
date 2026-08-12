CREATE TABLE payment_fx_quotes (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    purpose VARCHAR(32) NOT NULL,
    session_id UUID REFERENCES tour_sessions(id),
    participant_count INTEGER,
    base_amount_minor BIGINT NOT NULL,
    base_currency_code VARCHAR(3) NOT NULL,
    charge_amount_minor BIGINT NOT NULL,
    charge_currency_code VARCHAR(3) NOT NULL,
    fx_rate NUMERIC(24, 12) NOT NULL,
    rate_source VARCHAR(64) NOT NULL,
    rate_date DATE NOT NULL,
    quoted_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_payment_fx_quote_purpose
        CHECK (purpose IN ('WALLET_TOP_UP', 'TOUR_BOOKING')),
    CONSTRAINT chk_payment_fx_quote_shape CHECK (
        (purpose = 'TOUR_BOOKING' AND session_id IS NOT NULL AND participant_count > 0)
        OR (purpose = 'WALLET_TOP_UP' AND session_id IS NULL AND participant_count IS NULL)
    ),
    CONSTRAINT chk_payment_fx_quote_base_amount CHECK (base_amount_minor > 0),
    CONSTRAINT chk_payment_fx_quote_base_currency CHECK (base_currency_code = 'USD'),
    CONSTRAINT chk_payment_fx_quote_charge_amount CHECK (charge_amount_minor > 0),
    CONSTRAINT chk_payment_fx_quote_charge_currency
        CHECK (charge_currency_code IN ('USD', 'TRY', 'EUR', 'GBP', 'NOK', 'CHF')),
    CONSTRAINT chk_payment_fx_quote_rate CHECK (fx_rate > 0),
    CONSTRAINT chk_payment_fx_quote_expiry CHECK (expires_at > quoted_at)
);

CREATE INDEX idx_payment_fx_quote_user_expiry
    ON payment_fx_quotes(user_id, expires_at);

ALTER TABLE payments
    ADD COLUMN fx_quote_id UUID REFERENCES payment_fx_quotes(id);

ALTER TABLE payments
    ADD COLUMN charge_amount_minor BIGINT;

ALTER TABLE payments
    ADD COLUMN charge_currency_code VARCHAR(3);

ALTER TABLE payments
    ADD COLUMN fx_rate NUMERIC(24, 12);

ALTER TABLE payments
    ADD COLUMN fx_rate_source VARCHAR(64);

ALTER TABLE payments
    ADD COLUMN fx_quoted_at TIMESTAMP(6) WITH TIME ZONE;

UPDATE payments
SET charge_amount_minor = amount_minor,
    charge_currency_code = currency_code,
    fx_rate = 1.000000000000,
    fx_rate_source = 'LEGACY_USD',
    fx_quoted_at = created_at
WHERE method = 'HOSTED_CARD';

ALTER TABLE payments
    ADD CONSTRAINT uq_payment_fx_quote UNIQUE (fx_quote_id);

ALTER TABLE payments
    ADD CONSTRAINT chk_payment_charge_snapshot CHECK (
        (method = 'WALLET'
            AND fx_quote_id IS NULL
            AND charge_amount_minor IS NULL
            AND charge_currency_code IS NULL
            AND fx_rate IS NULL
            AND fx_rate_source IS NULL
            AND fx_quoted_at IS NULL)
        OR (method = 'HOSTED_CARD'
            AND charge_amount_minor > 0
            AND charge_currency_code IN ('USD', 'TRY', 'EUR', 'GBP', 'NOK', 'CHF')
            AND fx_rate > 0
            AND fx_rate_source IS NOT NULL
            AND fx_quoted_at IS NOT NULL)
    );

ALTER TABLE refunds
    ADD COLUMN charge_amount_minor BIGINT;

ALTER TABLE refunds
    ADD COLUMN charge_currency_code VARCHAR(3);

UPDATE refunds
SET charge_amount_minor = amount_minor,
    charge_currency_code = currency_code;

ALTER TABLE refunds
    ALTER COLUMN charge_amount_minor SET NOT NULL;

ALTER TABLE refunds
    ALTER COLUMN charge_currency_code SET NOT NULL;

ALTER TABLE refunds
    ADD CONSTRAINT chk_refund_charge_amount CHECK (charge_amount_minor > 0);

ALTER TABLE refunds
    ADD CONSTRAINT chk_refund_charge_currency
        CHECK (charge_currency_code IN ('USD', 'TRY', 'EUR', 'GBP', 'NOK', 'CHF'));
