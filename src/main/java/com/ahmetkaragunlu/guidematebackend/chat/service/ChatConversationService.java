package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatReadState;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatConversationResponse;
import com.ahmetkaragunlu.guidematebackend.chat.mapper.ChatMapper;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatMessageRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatReadStateRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ConversationUnreadCount;
import com.ahmetkaragunlu.guidematebackend.common.dto.UnreadCountResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ChatConversationService {

    private final ChatConversationRepository conversationRepository;
    private final ChatMessageRepository messageRepository;
    private final ChatReadStateRepository readStateRepository;
    private final UserRepository userRepository;
    private final ChatMapper chatMapper;
    private final Clock clock;

    @Transactional
    public ChatConversationResponse findOrCreate(User currentUser, Long remoteUserId) {
        ParticipantPair participants = lockAndValidateParticipants(currentUser.getId(), remoteUserId);
        ChatConversation conversation = conversationRepository
                .findByGuide_IdAndTourist_Id(participants.guide().getId(), participants.tourist().getId())
                .orElseGet(() -> createConversation(participants));
        ChatMessage lastMessage = messageRepository
                .findFirstByConversation_IdOrderBySentAtDescIdDesc(conversation.getId())
                .orElse(null);
        long unreadCount = unreadCounts(List.of(conversation.getId()), currentUser.getId())
                .getOrDefault(conversation.getId(), 0L);
        return chatMapper.toConversation(conversation, lastMessage, unreadCount);
    }

    @Transactional(readOnly = true)
    public List<ChatConversationResponse> getConversations(User currentUser) {
        List<ChatConversation> conversations = conversationRepository.findAllForParticipant(currentUser.getId());
        if (conversations.isEmpty()) {
            return List.of();
        }
        List<UUID> conversationIds = conversations.stream().map(ChatConversation::getId).toList();
        Map<UUID, ChatMessage> latestMessages = latestMessages(conversationIds);
        Map<UUID, Long> unreadCounts = unreadCounts(conversationIds, currentUser.getId());
        return conversations.stream()
                .map(conversation -> chatMapper.toConversation(
                        conversation,
                        latestMessages.get(conversation.getId()),
                        unreadCounts.getOrDefault(conversation.getId(), 0L)
                ))
                .sorted(Comparator
                        .comparing(ChatConversationResponse::lastActivityAt)
                        .reversed()
                        .thenComparing(ChatConversationResponse::chatId))
                .toList();
    }

    @Transactional
    public UnreadCountResponse markRead(User currentUser, UUID conversationId) {
        ChatConversation conversation = conversationRepository.findParticipantConversationForUpdate(
                        conversationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.CHAT_NOT_FOUND));
        ChatReadState readState = readStateRepository
                .findByIdConversationIdAndIdUserId(conversationId, currentUser.getId())
                .orElseGet(() -> new ChatReadState(
                        conversation,
                        userRepository.getReferenceById(currentUser.getId()),
                        clock.instant()
                ));
        messageRepository.findFirstByConversation_IdOrderBySentAtDescIdDesc(conversationId)
                .ifPresent(message -> readState.markRead(message, clock.instant()));
        readStateRepository.save(readState);
        return unreadCount(currentUser);
    }

    @Transactional(readOnly = true)
    public UnreadCountResponse unreadCount(User currentUser) {
        return new UnreadCountResponse(messageRepository.countUnread(currentUser.getId()));
    }

    private ChatConversation createConversation(ParticipantPair participants) {
        ChatConversation conversation = conversationRepository.saveAndFlush(
                new ChatConversation(participants.guide(), participants.tourist())
        );
        Instant now = clock.instant();
        readStateRepository.saveAll(List.of(
                new ChatReadState(conversation, participants.guide(), now),
                new ChatReadState(conversation, participants.tourist(), now)
        ));
        return conversation;
    }

    private ParticipantPair lockAndValidateParticipants(Long currentUserId, Long remoteUserId) {
        if (remoteUserId == null || currentUserId.equals(remoteUserId)) {
            throw new BusinessException(ErrorCode.CHAT_PARTICIPANT_INVALID);
        }
        Long firstId = Math.min(currentUserId, remoteUserId);
        Long secondId = Math.max(currentUserId, remoteUserId);
        User first = userRepository.findByIdForUpdate(firstId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        User second = userRepository.findByIdForUpdate(secondId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        User current = currentUserId.equals(firstId) ? first : second;
        User remote = remoteUserId.equals(firstId) ? first : second;
        requireActiveRole(current);
        requireActiveRole(remote);

        if (current.hasRole(RoleType.ROLE_GUIDE) && remote.hasRole(RoleType.ROLE_TOURIST)) {
            return new ParticipantPair(current, remote);
        }
        if (current.hasRole(RoleType.ROLE_TOURIST) && remote.hasRole(RoleType.ROLE_GUIDE)) {
            return new ParticipantPair(remote, current);
        }
        throw new BusinessException(ErrorCode.CHAT_PARTICIPANT_INVALID);
    }

    private void requireActiveRole(User user) {
        if (user.getAccountStatus() != AccountStatus.ACTIVE || user.getRole() == null) {
            throw new BusinessException(ErrorCode.CHAT_PARTICIPANT_INVALID);
        }
    }

    private Map<UUID, ChatMessage> latestMessages(List<UUID> conversationIds) {
        Map<UUID, ChatMessage> latestMessages = new HashMap<>();
        messageRepository.findLatestForConversations(conversationIds)
                .forEach(message -> latestMessages.putIfAbsent(message.getConversation().getId(), message));
        return latestMessages;
    }

    private Map<UUID, Long> unreadCounts(List<UUID> conversationIds, Long userId) {
        return messageRepository.countUnreadByConversationIds(conversationIds, userId).stream()
                .collect(Collectors.toMap(
                        ConversationUnreadCount::getConversationId,
                        ConversationUnreadCount::getUnreadCount
                ));
    }

    private record ParticipantPair(User guide, User tourist) {
    }
}
