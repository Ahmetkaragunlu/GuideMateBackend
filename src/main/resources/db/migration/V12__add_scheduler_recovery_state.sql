ALTER TABLE payments
    ADD COLUMN reconciliation_attempt_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE payments
    ADD COLUMN last_reconciliation_at TIMESTAMP(6) WITH TIME ZONE;

ALTER TABLE payments
    ADD CONSTRAINT chk_payment_reconciliation_attempt_count
        CHECK (reconciliation_attempt_count >= 0);

CREATE INDEX idx_payment_reconciliation
    ON payments(status, expires_at, last_reconciliation_at);

ALTER TABLE refunds
    ADD COLUMN processing_attempt_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE refunds
    ADD COLUMN last_processing_attempt_at TIMESTAMP(6) WITH TIME ZONE;

ALTER TABLE refunds
    ADD CONSTRAINT chk_refund_processing_attempt_count
        CHECK (processing_attempt_count >= 0);

CREATE INDEX idx_refund_processing_retry
    ON refunds(status, last_processing_attempt_at);

ALTER TABLE notifications
    ADD COLUMN deduplication_key VARCHAR(160);

ALTER TABLE notifications
    ADD COLUMN push_attempt_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE notifications
    ADD COLUMN next_push_attempt_at TIMESTAMP(6) WITH TIME ZONE;

ALTER TABLE notifications
    ADD CONSTRAINT chk_notification_push_attempt_count
        CHECK (push_attempt_count >= 0);

ALTER TABLE notifications
    ADD CONSTRAINT uq_notification_deduplication
        UNIQUE (recipient_id, type, deduplication_key);

DROP INDEX idx_notification_push_retry;
CREATE INDEX idx_notification_push_retry
    ON notifications(push_status, next_push_attempt_at, push_attempt_count);

CREATE INDEX idx_device_registration_cleanup
    ON device_registrations(active, last_seen_at);

ALTER TABLE reservations
    ADD COLUMN upcoming_reminder_sent_at TIMESTAMP(6) WITH TIME ZONE;

CREATE INDEX idx_reservation_upcoming_reminder
    ON reservations(status, upcoming_reminder_sent_at, session_id);

ALTER TABLE tour_sessions
    ADD COLUMN upcoming_reminder_sent_at TIMESTAMP(6) WITH TIME ZONE;

CREATE INDEX idx_tour_session_upcoming_reminder
    ON tour_sessions(status, upcoming_reminder_sent_at, starts_at);
