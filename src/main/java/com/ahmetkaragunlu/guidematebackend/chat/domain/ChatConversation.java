package com.ahmetkaragunlu.guidematebackend.chat.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Getter
@Entity
@Table(
        name = "chat_conversations",
        indexes = {
                @Index(name = "idx_chat_conversation_guide_updated", columnList = "guide_id, updated_at"),
                @Index(name = "idx_chat_conversation_tourist_updated", columnList = "tourist_id, updated_at")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uq_chat_conversation_participants",
                columnNames = {"guide_id", "tourist_id"}
        )
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ChatConversation extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "guide_id", nullable = false, updatable = false)
    private User guide;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tourist_id", nullable = false, updatable = false)
    private User tourist;

    public ChatConversation(User guide, User tourist) {
        this.guide = Objects.requireNonNull(guide);
        this.tourist = Objects.requireNonNull(tourist);
        if (guide.getId().equals(tourist.getId())) {
            throw new IllegalArgumentException("Chat participants must be different users");
        }
    }

    public boolean hasParticipant(Long userId) {
        return guide.getId().equals(userId) || tourist.getId().equals(userId);
    }

    public User otherParticipant(Long userId) {
        if (guide.getId().equals(userId)) {
            return tourist;
        }
        if (tourist.getId().equals(userId)) {
            return guide;
        }
        throw new IllegalArgumentException("User is not a chat participant");
    }
}
