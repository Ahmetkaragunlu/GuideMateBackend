ALTER TABLE tour_sessions
    ADD COLUMN cancellation_idempotency_key VARCHAR(128);

UPDATE tour_sessions
SET cancellation_idempotency_key = 'legacy-' || id
WHERE status = 'CANCELLED'
  AND cancellation_idempotency_key IS NULL;

ALTER TABLE tour_sessions
    DROP CONSTRAINT chk_tour_session_cancellation_fields;

ALTER TABLE tour_sessions
    ADD CONSTRAINT chk_tour_session_cancellation_fields
        CHECK (
            (status = 'CANCELLED' AND cancellation_actor IS NOT NULL
                AND cancellation_reason IS NOT NULL AND cancelled_at IS NOT NULL
                AND cancellation_idempotency_key IS NOT NULL)
            OR
            (status <> 'CANCELLED' AND cancellation_actor IS NULL
                AND cancellation_reason IS NULL AND cancelled_at IS NULL
                AND cancellation_idempotency_key IS NULL)
        );
