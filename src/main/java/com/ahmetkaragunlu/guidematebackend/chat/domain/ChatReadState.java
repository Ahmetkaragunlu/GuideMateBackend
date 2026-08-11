package com.ahmetkaragunlu.guidematebackend.chat.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Getter
@Entity
@Table(name = "chat_read_state")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ChatReadState {

    @EmbeddedId
    private ChatReadStateId id;

    @MapsId("conversationId")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "conversation_id", nullable = false, updatable = false)
    private ChatConversation conversation;

    @MapsId("userId")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "last_read_message_id")
    private ChatMessage lastReadMessage;

    @Column(name = "read_at", nullable = false)
    private Instant readAt;

    public ChatReadState(ChatConversation conversation, User user, Instant readAt) {
        this.conversation = Objects.requireNonNull(conversation);
        this.user = Objects.requireNonNull(user);
        this.readAt = Objects.requireNonNull(readAt);
    }

    public void markRead(ChatMessage message, Instant readAt) {
        this.lastReadMessage = message;
        this.readAt = Objects.requireNonNull(readAt);
    }
}
