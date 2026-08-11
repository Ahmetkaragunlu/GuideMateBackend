package com.ahmetkaragunlu.guidematebackend.chat.repository;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatReadState;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatReadStateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ChatReadStateRepository extends JpaRepository<ChatReadState, ChatReadStateId> {

    Optional<ChatReadState> findByIdConversationIdAndIdUserId(UUID conversationId, Long userId);
}
