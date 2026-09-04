ALTER TABLE chat_read_state
    ADD COLUMN cleared_at TIMESTAMP(6) WITH TIME ZONE,
    ADD COLUMN last_clear_request_id UUID;

CREATE INDEX idx_chat_read_state_user_cleared
    ON chat_read_state(user_id, cleared_at);
