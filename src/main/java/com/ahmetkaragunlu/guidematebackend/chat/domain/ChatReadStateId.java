package com.ahmetkaragunlu.guidematebackend.chat.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
public record ChatReadStateId(
        @Column(name = "conversation_id") UUID conversationId,
        @Column(name = "user_id") Long userId
) implements Serializable {
}
