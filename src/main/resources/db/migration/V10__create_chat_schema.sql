CREATE TABLE chat_conversations (
    id UUID PRIMARY KEY,
    guide_id BIGINT NOT NULL REFERENCES users(id),
    tourist_id BIGINT NOT NULL REFERENCES users(id),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_chat_conversation_participants UNIQUE (guide_id, tourist_id),
    CONSTRAINT chk_chat_conversation_distinct_users CHECK (guide_id <> tourist_id)
);

CREATE INDEX idx_chat_conversation_guide_updated
    ON chat_conversations(guide_id, updated_at DESC);
CREATE INDEX idx_chat_conversation_tourist_updated
    ON chat_conversations(tourist_id, updated_at DESC);

CREATE TABLE chat_messages (
    id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    sender_id BIGINT NOT NULL REFERENCES users(id),
    client_message_id UUID NOT NULL,
    body VARCHAR(2000) NOT NULL,
    sent_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_chat_message_client_id UNIQUE (sender_id, client_message_id),
    CONSTRAINT chk_chat_message_body CHECK (
        CHAR_LENGTH(TRIM(body)) BETWEEN 1 AND 2000
    )
);

CREATE INDEX idx_chat_message_conversation_sent
    ON chat_messages(conversation_id, sent_at DESC, id DESC);

CREATE TABLE chat_read_state (
    conversation_id UUID NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_read_message_id UUID REFERENCES chat_messages(id) ON DELETE SET NULL,
    read_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX idx_chat_read_state_user ON chat_read_state(user_id);
