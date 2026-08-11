package com.ahmetkaragunlu.guidematebackend.chat.repository;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ChatConversationRepository extends JpaRepository<ChatConversation, UUID> {

    @EntityGraph(attributePaths = {"guide", "guide.role", "tourist", "tourist.role"})
    Optional<ChatConversation> findByGuide_IdAndTourist_Id(Long guideId, Long touristId);

    @EntityGraph(attributePaths = {"guide", "guide.role", "tourist", "tourist.role"})
    @Query("""
            SELECT conversation FROM ChatConversation conversation
            WHERE conversation.id = :conversationId
              AND (conversation.guide.id = :userId OR conversation.tourist.id = :userId)
            """)
    Optional<ChatConversation> findParticipantConversation(
            @Param("conversationId") UUID conversationId,
            @Param("userId") Long userId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"guide", "guide.role", "tourist", "tourist.role"})
    @Query("""
            SELECT conversation FROM ChatConversation conversation
            WHERE conversation.id = :conversationId
              AND (conversation.guide.id = :userId OR conversation.tourist.id = :userId)
            """)
    Optional<ChatConversation> findParticipantConversationForUpdate(
            @Param("conversationId") UUID conversationId,
            @Param("userId") Long userId
    );

    @EntityGraph(attributePaths = {"guide", "guide.role", "tourist", "tourist.role"})
    @Query("""
            SELECT conversation FROM ChatConversation conversation
            WHERE conversation.guide.id = :userId OR conversation.tourist.id = :userId
            """)
    List<ChatConversation> findAllForParticipant(@Param("userId") Long userId);
}
