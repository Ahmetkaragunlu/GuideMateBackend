package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.dto.request.SendChatMessageRequest;
import com.ahmetkaragunlu.guidematebackend.chat.mapper.ChatMapper;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatMessageRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatReadStateRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChatMessageServiceTest {

    @Mock private ChatConversationRepository conversationRepository;
    @Mock private ChatMessageRepository messageRepository;
    @Mock private ChatReadStateRepository readStateRepository;
    @Mock private NotificationPublisher notificationPublisher;
    @Mock private ApplicationEventPublisher eventPublisher;
    @Mock private ChatMapper chatMapper;

    private ChatMessageService service;

    @BeforeEach
    void setUp() {
        service = new ChatMessageService(
                conversationRepository,
                messageRepository,
                readStateRepository,
                notificationPublisher,
                eventPublisher,
                chatMapper,
                Clock.systemUTC()
        );
    }

    @Test
    void rejectsBlankAndOversizedMessagesBeforePersistence() {
        UUID conversationId = UUID.randomUUID();
        User current = sender(1);
        ChatConversation conversation = conversation(current);
        when(conversationRepository.findParticipantConversationForUpdate(conversationId, current.getId()))
                .thenReturn(Optional.of(conversation));

        assertError(() -> service.send(current, conversationId, request("   ")), ErrorCode.VALIDATION_FAILED);
        assertError(
                () -> service.send(current, conversationId, request("x".repeat(2001))),
                ErrorCode.CHAT_MESSAGE_TOO_LONG
        );
        verify(messageRepository, never()).saveAndFlush(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void rejectsStaleAuthenticatedPrincipal() {
        UUID conversationId = UUID.randomUUID();
        User current = mock(User.class);
        User persistedSender = mock(User.class);
        when(current.getId()).thenReturn(1L);
        when(current.getTokenVersion()).thenReturn(1);
        when(persistedSender.isEnabled()).thenReturn(true);
        when(persistedSender.getTokenVersion()).thenReturn(2);
        ChatConversation conversation = mock(ChatConversation.class);
        when(conversation.participant(current.getId())).thenReturn(persistedSender);
        when(conversationRepository.findParticipantConversationForUpdate(conversationId, current.getId()))
                .thenReturn(Optional.of(conversation));

        assertError(() -> service.send(current, conversationId, request("Merhaba")), ErrorCode.FORBIDDEN);
    }

    @Test
    void rejectsReusedClientMessageIdForDifferentContent() {
        UUID conversationId = UUID.randomUUID();
        User current = sender(1);
        ChatConversation conversation = conversation(current);
        ChatMessage duplicate = mock(ChatMessage.class);
        ChatConversation duplicateConversation = mock(ChatConversation.class);
        when(duplicate.getConversation()).thenReturn(duplicateConversation);
        when(duplicateConversation.getId()).thenReturn(conversationId);
        when(duplicate.getBody()).thenReturn("Eski mesaj");
        when(conversationRepository.findParticipantConversationForUpdate(conversationId, current.getId()))
                .thenReturn(Optional.of(conversation));
        when(messageRepository.findBySender_IdAndClientMessageId(current.getId(), requestId()))
                .thenReturn(Optional.of(duplicate));

        assertError(() -> service.send(current, conversationId, request("Yeni mesaj")), ErrorCode.IDEMPOTENCY_CONFLICT);
        verify(messageRepository, never()).saveAndFlush(org.mockito.ArgumentMatchers.any());
    }

    private User sender(int tokenVersion) {
        User sender = mock(User.class);
        when(sender.getId()).thenReturn(1L);
        when(sender.isEnabled()).thenReturn(true);
        when(sender.getTokenVersion()).thenReturn(tokenVersion);
        when(sender.hasRole(any(RoleType.class)))
                .thenAnswer(invocation -> invocation.getArgument(0) == RoleType.ROLE_TOURIST);
        return sender;
    }

    private ChatConversation conversation(User sender) {
        ChatConversation conversation = mock(ChatConversation.class);
        when(conversation.participant(sender.getId())).thenReturn(sender);
        return conversation;
    }

    private SendChatMessageRequest request(String body) {
        return new SendChatMessageRequest(requestId(), body);
    }

    private UUID requestId() {
        return UUID.fromString("11111111-1111-4111-8111-111111111111");
    }

    private void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, ErrorCode expected) {
        assertThatThrownBy(action)
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(expected));
    }
}
