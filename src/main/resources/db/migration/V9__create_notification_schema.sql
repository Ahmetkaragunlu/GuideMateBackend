CREATE TABLE notification_preferences (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    upcoming_tour_reminders_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    chat_messages_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    reservation_updates_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    review_requests_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    payments_and_earnings_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    new_reviews_enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE device_tokens (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    installation_id UUID NOT NULL,
    fcm_token VARCHAR(4096) NOT NULL,
    platform VARCHAR(16) NOT NULL,
    active BOOLEAN NOT NULL,
    last_seen_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_device_token_installation UNIQUE (installation_id),
    CONSTRAINT uq_device_token_value UNIQUE (fcm_token),
    CONSTRAINT chk_device_token_platform CHECK (platform = 'ANDROID')
);

CREATE INDEX idx_device_token_user_active ON device_tokens(user_id, active);

CREATE TABLE notifications (
    id UUID PRIMARY KEY,
    recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    payload JSONB NOT NULL,
    read_at TIMESTAMP(6) WITH TIME ZONE,
    push_status VARCHAR(16) NOT NULL,
    last_push_attempt_at TIMESTAMP(6) WITH TIME ZONE,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_notification_push_status CHECK (
        push_status IN ('NOT_REQUESTED', 'PENDING', 'SENT', 'FAILED')
    )
);

CREATE INDEX idx_notification_recipient_created
    ON notifications(recipient_id, created_at DESC, id DESC);
CREATE INDEX idx_notification_recipient_unread
    ON notifications(recipient_id, read_at);
CREATE INDEX idx_notification_push_retry
    ON notifications(push_status, last_push_attempt_at);
