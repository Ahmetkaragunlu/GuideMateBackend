CREATE TABLE reservations (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES tour_sessions(id),
    tourist_id BIGINT NOT NULL REFERENCES users(id),
    participant_count INTEGER NOT NULL,
    unit_price_minor BIGINT NOT NULL,
    total_price_minor BIGINT NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    status VARCHAR(32) NOT NULL,
    hold_expires_at TIMESTAMP(6) WITH TIME ZONE,
    cancellation_actor VARCHAR(16),
    cancellation_reason VARCHAR(1000),
    cancelled_at TIMESTAMP(6) WITH TIME ZONE,
    cancellation_refund_eligibility VARCHAR(16),
    cancellation_policy_code VARCHAR(64) NOT NULL,
    cancellation_policy_version INTEGER NOT NULL,
    snapshot_version INTEGER NOT NULL,
    purchase_snapshot JSONB NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    cancellation_idempotency_key VARCHAR(128),
    active_guard BOOLEAN,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_reservation_participant_count CHECK (participant_count > 0),
    CONSTRAINT chk_reservation_unit_price CHECK (unit_price_minor > 0),
    CONSTRAINT chk_reservation_total_price CHECK (
        total_price_minor > 0
        AND total_price_minor = unit_price_minor * participant_count
    ),
    CONSTRAINT chk_reservation_currency CHECK (currency_code = 'USD'),
    CONSTRAINT chk_reservation_status CHECK (
        status IN ('PENDING_PAYMENT', 'CONFIRMED', 'COMPLETED', 'CANCELLED', 'EXPIRED')
    ),
    CONSTRAINT chk_reservation_cancellation_actor CHECK (
        cancellation_actor IS NULL
        OR cancellation_actor IN ('TOURIST', 'GUIDE', 'ADMIN', 'SYSTEM')
    ),
    CONSTRAINT chk_reservation_cancellation_fields CHECK (
        (status = 'CANCELLED' AND cancellation_actor IS NOT NULL AND cancelled_at IS NOT NULL
            AND cancellation_refund_eligibility IS NOT NULL)
        OR
        (status <> 'CANCELLED' AND cancellation_actor IS NULL
            AND cancellation_reason IS NULL AND cancelled_at IS NULL
            AND cancellation_idempotency_key IS NULL
            AND cancellation_refund_eligibility IS NULL)
    ),
    CONSTRAINT chk_reservation_refund_eligibility CHECK (
        cancellation_refund_eligibility IS NULL
        OR cancellation_refund_eligibility IN ('FULL_REFUND', 'NO_REFUND', 'NOT_APPLICABLE')
    ),
    CONSTRAINT chk_reservation_active_guard CHECK (
        (status IN ('PENDING_PAYMENT', 'CONFIRMED') AND active_guard = TRUE)
        OR (status NOT IN ('PENDING_PAYMENT', 'CONFIRMED') AND active_guard IS NULL)
    ),
    CONSTRAINT chk_reservation_policy_version CHECK (cancellation_policy_version > 0),
    CONSTRAINT chk_reservation_snapshot_version CHECK (snapshot_version > 0),
    CONSTRAINT uq_reservation_active UNIQUE (session_id, tourist_id, active_guard),
    CONSTRAINT uq_reservation_booking_idempotency UNIQUE (tourist_id, idempotency_key),
    CONSTRAINT uq_reservation_cancel_idempotency UNIQUE (tourist_id, cancellation_idempotency_key)
);

CREATE INDEX idx_reservation_session_status ON reservations(session_id, status);
CREATE INDEX idx_reservation_tourist_created ON reservations(tourist_id, created_at);
CREATE INDEX idx_reservation_hold_expiry ON reservations(status, hold_expires_at);

CREATE TABLE reviews (
    id UUID PRIMARY KEY,
    reservation_id UUID NOT NULL UNIQUE REFERENCES reservations(id),
    rating SMALLINT NOT NULL,
    comment VARCHAR(2000),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_review_rating CHECK (rating BETWEEN 1 AND 5),
    CONSTRAINT chk_review_comment CHECK (
        comment IS NULL OR CHAR_LENGTH(TRIM(comment)) BETWEEN 1 AND 2000
    )
);

CREATE INDEX idx_review_created ON reviews(created_at);
