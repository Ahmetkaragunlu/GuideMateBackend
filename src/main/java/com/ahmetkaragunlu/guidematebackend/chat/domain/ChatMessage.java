package com.ahmetkaragunlu.guidematebackend.chat.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "chat_messages",
        indexes = @Index(
                name = "idx_chat_message_conversation_sent",
                columnList = "conversation_id, sent_at, id"
        ),
        uniqueConstraints = @UniqueConstraint(
                name = "uq_chat_message_client_id",
                columnNames = {"sender_id", "client_message_id"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ChatMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "conversation_id", nullable = false, updatable = false)
    private ChatConversation conversation;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sender_id", nullable = false, updatable = false)
    private User sender;

    @Column(name = "client_message_id", nullable = false, updatable = false)
    private UUID clientMessageId;

    @Column(name = "body", nullable = false, updatable = false, length = 2000)
    private String body;

    @Column(name = "sent_at", nullable = false, updatable = false)
    private Instant sentAt;

    public ChatMessage(
            ChatConversation conversation,
            User sender,
            UUID clientMessageId,
            String body,
            Instant sentAt
    ) {
        this.conversation = Objects.requireNonNull(conversation);
        this.sender = Objects.requireNonNull(sender);
        this.clientMessageId = Objects.requireNonNull(clientMessageId);
        this.body = Objects.requireNonNull(body);
        this.sentAt = Objects.requireNonNull(sentAt);
    }
}
