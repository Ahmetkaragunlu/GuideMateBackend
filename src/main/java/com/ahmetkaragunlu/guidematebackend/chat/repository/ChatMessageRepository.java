package com.ahmetkaragunlu.guidematebackend.chat.repository;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ChatMessageRepository extends JpaRepository<ChatMessage, UUID> {

    Optional<ChatMessage> findBySender_IdAndClientMessageId(Long senderId, UUID clientMessageId);

    Optional<ChatMessage> findFirstByConversation_IdOrderBySentAtDescIdDesc(UUID conversationId);

    @Query("""
            SELECT message FROM ChatMessage message
            WHERE message.conversation.id = :conversationId
            ORDER BY message.sentAt DESC, message.id DESC
            """)
    List<ChatMessage> findFirstPage(
            @Param("conversationId") UUID conversationId,
            Pageable pageable
    );

    @Query("""
            SELECT message FROM ChatMessage message
            WHERE message.conversation.id = :conversationId
              AND (
                  message.sentAt < :cursorSentAt
                  OR (message.sentAt = :cursorSentAt AND message.id < :cursorId)
              )
            ORDER BY message.sentAt DESC, message.id DESC
            """)
    List<ChatMessage> findPageBefore(
            @Param("conversationId") UUID conversationId,
            @Param("cursorSentAt") Instant cursorSentAt,
            @Param("cursorId") UUID cursorId,
            Pageable pageable
    );

    @Query("""
            SELECT message FROM ChatMessage message
            WHERE message.conversation.id IN :conversationIds
              AND message.sentAt = (
                  SELECT MAX(candidate.sentAt) FROM ChatMessage candidate
                  WHERE candidate.conversation.id = message.conversation.id
              )
            ORDER BY message.sentAt DESC, message.id DESC
            """)
    List<ChatMessage> findLatestForConversations(
            @Param("conversationIds") Collection<UUID> conversationIds
    );

    @Query("""
            SELECT message.conversation.id AS conversationId, COUNT(message) AS unreadCount
            FROM ChatMessage message, ChatReadState readState
            LEFT JOIN readState.lastReadMessage lastReadMessage
            WHERE message.conversation.id IN :conversationIds
              AND readState.conversation.id = message.conversation.id
              AND readState.user.id = :userId
              AND message.sender.id <> :userId
              AND (
                  lastReadMessage IS NULL
                  OR message.sentAt > lastReadMessage.sentAt
                  OR (message.sentAt = lastReadMessage.sentAt AND message.id > lastReadMessage.id)
              )
            GROUP BY message.conversation.id
            """)
    List<ConversationUnreadCount> countUnreadByConversationIds(
            @Param("conversationIds") Collection<UUID> conversationIds,
            @Param("userId") Long userId
    );

    @Query("""
            SELECT COUNT(message)
            FROM ChatMessage message, ChatReadState readState
            LEFT JOIN readState.lastReadMessage lastReadMessage
            WHERE readState.conversation.id = message.conversation.id
              AND readState.user.id = :userId
              AND message.sender.id <> :userId
              AND (
                  lastReadMessage IS NULL
                  OR message.sentAt > lastReadMessage.sentAt
                  OR (message.sentAt = lastReadMessage.sentAt AND message.id > lastReadMessage.id)
              )
            """)
    long countUnread(@Param("userId") Long userId);
}
