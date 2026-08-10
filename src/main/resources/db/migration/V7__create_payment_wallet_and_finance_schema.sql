CREATE TABLE payments (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    purpose VARCHAR(32) NOT NULL,
    method VARCHAR(32) NOT NULL,
    reservation_id UUID REFERENCES reservations(id),
    amount_minor BIGINT NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    status VARCHAR(32) NOT NULL,
    provider VARCHAR(32),
    provider_payment_id VARCHAR(255) UNIQUE,
    provider_transaction_id VARCHAR(255) UNIQUE,
    provider_token_encrypted TEXT,
    provider_token_fingerprint VARCHAR(64) UNIQUE,
    provider_conversation_id VARCHAR(255),
    payment_page_url TEXT,
    idempotency_key VARCHAR(128) NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE,
    verified_at TIMESTAMP(6) WITH TIME ZONE,
    failure_code VARCHAR(64),
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_payment_idempotency UNIQUE (user_id, purpose, idempotency_key),
    CONSTRAINT chk_payment_amount CHECK (amount_minor > 0),
    CONSTRAINT chk_payment_currency CHECK (currency_code = 'USD'),
    CONSTRAINT chk_payment_purpose CHECK (purpose IN ('WALLET_TOP_UP', 'TOUR_BOOKING')),
    CONSTRAINT chk_payment_method CHECK (method IN ('WALLET', 'HOSTED_CARD')),
    CONSTRAINT chk_payment_status CHECK (
        status IN ('PENDING', 'REQUIRES_ACTION', 'VERIFYING', 'SUCCEEDED',
                   'FAILED', 'CANCELLED', 'TIMEOUT')
    ),
    CONSTRAINT chk_payment_provider CHECK (
        (method = 'WALLET' AND provider IS NULL)
        OR (method = 'HOSTED_CARD' AND provider = 'IYZICO')
    ),
    CONSTRAINT chk_payment_reservation CHECK (
        (purpose = 'TOUR_BOOKING' AND reservation_id IS NOT NULL)
        OR (purpose = 'WALLET_TOP_UP' AND reservation_id IS NULL)
    )
);

CREATE INDEX idx_payment_user_created ON payments(user_id, created_at);
CREATE INDEX idx_payment_reservation ON payments(reservation_id);
CREATE INDEX idx_payment_status_updated ON payments(status, updated_at);

CREATE TABLE payment_events (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES payments(id),
    event_type VARCHAR(64) NOT NULL,
    provider_event_id VARCHAR(128) UNIQUE,
    payload_hash VARCHAR(64),
    provider_status VARCHAR(64),
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_payment_event_payment_occurred ON payment_events(payment_id, occurred_at);

CREATE TABLE refunds (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES payments(id),
    requested_by BIGINT NOT NULL REFERENCES users(id),
    amount_minor BIGINT NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    status VARCHAR(32) NOT NULL,
    provider_refund_id VARCHAR(255) UNIQUE,
    idempotency_key VARCHAR(128) NOT NULL,
    failure_code VARCHAR(64),
    requested_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP(6) WITH TIME ZONE,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_refund_idempotency UNIQUE (payment_id, idempotency_key),
    CONSTRAINT chk_refund_amount CHECK (amount_minor > 0),
    CONSTRAINT chk_refund_currency CHECK (currency_code = 'USD'),
    CONSTRAINT chk_refund_status CHECK (
        status IN ('REQUESTED', 'PROCESSING', 'SUCCEEDED', 'FAILED', 'MANUAL_REVIEW')
    )
);

CREATE INDEX idx_refund_payment ON refunds(payment_id);
CREATE INDEX idx_refund_status_updated ON refunds(status, updated_at);

CREATE TABLE wallets (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE REFERENCES users(id),
    currency_code VARCHAR(3) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_wallet_currency CHECK (currency_code = 'USD')
);

CREATE TABLE wallet_ledger_entries (
    id UUID PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id),
    direction VARCHAR(16) NOT NULL,
    type VARCHAR(32) NOT NULL,
    amount_minor BIGINT NOT NULL,
    reference_type VARCHAR(32) NOT NULL,
    reference_id UUID NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_wallet_ledger_idempotency UNIQUE (wallet_id, idempotency_key),
    CONSTRAINT chk_wallet_ledger_direction CHECK (direction IN ('CREDIT', 'DEBIT')),
    CONSTRAINT chk_wallet_ledger_type CHECK (
        type IN ('TOP_UP', 'TOUR_PURCHASE', 'REFUND', 'GUIDE_EARNING',
                 'WITHDRAWAL', 'EARNING_REVERSAL')
    ),
    CONSTRAINT chk_wallet_ledger_amount CHECK (amount_minor > 0)
);

CREATE INDEX idx_wallet_ledger_wallet_occurred
    ON wallet_ledger_entries(wallet_id, occurred_at);
CREATE INDEX idx_wallet_ledger_reference
    ON wallet_ledger_entries(reference_type, reference_id);

CREATE TABLE guide_earnings (
    id UUID PRIMARY KEY,
    reservation_id UUID NOT NULL UNIQUE REFERENCES reservations(id),
    gross_minor BIGINT NOT NULL,
    platform_fee_minor BIGINT NOT NULL,
    net_minor BIGINT NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    status VARCHAR(16) NOT NULL,
    available_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    reversed_at TIMESTAMP(6) WITH TIME ZONE,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_guide_earning_amounts CHECK (
        gross_minor > 0
        AND platform_fee_minor >= 0
        AND net_minor > 0
        AND gross_minor = platform_fee_minor + net_minor
    ),
    CONSTRAINT chk_guide_earning_currency CHECK (currency_code = 'USD'),
    CONSTRAINT chk_guide_earning_status CHECK (status IN ('PENDING', 'AVAILABLE', 'REVERSED'))
);

CREATE INDEX idx_guide_earning_status_available ON guide_earnings(status, available_at);

CREATE TABLE bank_accounts (
    id UUID PRIMARY KEY,
    guide_id BIGINT NOT NULL REFERENCES users(id),
    iban_encrypted TEXT NOT NULL,
    iban_fingerprint VARCHAR(64) NOT NULL,
    masked_iban VARCHAR(34) NOT NULL,
    bank_code VARCHAR(8) NOT NULL,
    bank_name VARCHAR(128) NOT NULL,
    account_holder_name VARCHAR(160) NOT NULL,
    is_default BOOLEAN NOT NULL,
    default_guard BOOLEAN,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_bank_account_iban UNIQUE (guide_id, iban_fingerprint),
    CONSTRAINT uq_bank_account_default UNIQUE (guide_id, default_guard),
    CONSTRAINT chk_bank_account_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_bank_account_default_guard CHECK (
        (is_default = TRUE AND status = 'ACTIVE' AND default_guard = TRUE)
        OR ((is_default = FALSE OR status <> 'ACTIVE') AND default_guard IS NULL)
    )
);

CREATE INDEX idx_bank_account_guide_status ON bank_accounts(guide_id, status);

CREATE TABLE withdrawals (
    id UUID PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id),
    bank_account_id UUID NOT NULL REFERENCES bank_accounts(id),
    amount_minor BIGINT NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    status VARCHAR(16) NOT NULL,
    payout_mode VARCHAR(16) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    provider_reference VARCHAR(255),
    failure_code VARCHAR(64),
    requested_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP(6) WITH TIME ZONE,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_withdrawal_idempotency UNIQUE (wallet_id, idempotency_key),
    CONSTRAINT chk_withdrawal_amount CHECK (amount_minor > 0),
    CONSTRAINT chk_withdrawal_currency CHECK (currency_code = 'USD'),
    CONSTRAINT chk_withdrawal_status CHECK (
        status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED')
    ),
    CONSTRAINT chk_withdrawal_payout_mode CHECK (payout_mode IN ('IYZICO', 'SIMULATED'))
);

CREATE INDEX idx_withdrawal_wallet_requested ON withdrawals(wallet_id, requested_at);
CREATE INDEX idx_withdrawal_status_updated ON withdrawals(status, updated_at);
