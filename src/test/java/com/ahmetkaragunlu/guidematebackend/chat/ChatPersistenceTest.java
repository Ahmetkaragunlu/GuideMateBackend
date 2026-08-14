package com.ahmetkaragunlu.guidematebackend.chat;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatReadState;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.SendChatMessageRequest;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatMessageRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatReadStateRepository;
import com.ahmetkaragunlu.guidematebackend.chat.service.ChatMessageService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class ChatPersistenceTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private ChatConversationRepository conversationRepository;

    @Autowired
    private ChatMessageRepository messageRepository;

    @Autowired
    private ChatReadStateRepository readStateRepository;

    @Autowired
    private ChatMessageService chatMessageService;

    @Test
    void persistsReadStateAndQueriesUnreadAndCursorHistory() {
        User guide = createUser("guide-chat@example.com", RoleType.ROLE_GUIDE);
        User tourist = createUser("tourist-chat@example.com", RoleType.ROLE_TOURIST);
        ChatConversation conversation = conversationRepository.saveAndFlush(
                new ChatConversation(guide, tourist)
        );
        Instant initialReadAt = Instant.parse("2026-08-11T00:00:00Z");
        readStateRepository.saveAllAndFlush(List.of(
                new ChatReadState(conversation, guide, initialReadAt),
                new ChatReadState(conversation, tourist, initialReadAt)
        ));
        messageRepository.saveAndFlush(new ChatMessage(
                conversation,
                guide,
                UUID.randomUUID(),
                "First message",
                initialReadAt.plusSeconds(1)
        ));
        messageRepository.saveAndFlush(new ChatMessage(
                conversation,
                guide,
                UUID.randomUUID(),
                "Second message",
                initialReadAt.plusSeconds(1)
        ));

        assertThat(messageRepository.countUnread(tourist.getId())).isEqualTo(2);
        List<ChatMessage> newestFirst = messageRepository.findFirstPage(
                conversation.getId(),
                PageRequest.of(0, 10)
        );
        ChatMessage newest = newestFirst.get(0);
        ChatMessage oldest = newestFirst.get(1);
        assertThat(messageRepository.findPageBefore(
                conversation.getId(),
                newest.getSentAt(),
                newest.getId(),
                PageRequest.of(0, 10)
        )).extracting(ChatMessage::getId).containsExactly(oldest.getId());

        ChatReadState touristState = readStateRepository
                .findByIdConversationIdAndIdUserId(conversation.getId(), tourist.getId())
                .orElseThrow();
        touristState.markRead(oldest, initialReadAt.plusSeconds(2));
        readStateRepository.flush();

        assertThat(messageRepository.countUnread(tourist.getId())).isEqualTo(1);

        touristState.markRead(newest, initialReadAt.plusSeconds(3));
        readStateRepository.flush();

        assertThat(messageRepository.countUnread(tourist.getId())).isZero();
    }

    @Test
    void keepsClientMessageRetryIdempotentAndHidesConversationFromOutsider() {
        User guide = createUser("guide-retry@example.com", RoleType.ROLE_GUIDE);
        User tourist = createUser("tourist-retry@example.com", RoleType.ROLE_TOURIST);
        User outsider = createUser("outsider-retry@example.com", RoleType.ROLE_TOURIST);
        ChatConversation conversation = conversationRepository.saveAndFlush(
                new ChatConversation(guide, tourist)
        );
        readStateRepository.saveAllAndFlush(List.of(
                new ChatReadState(conversation, guide, Instant.now()),
                new ChatReadState(conversation, tourist, Instant.now())
        ));
        SendChatMessageRequest request = new SendChatMessageRequest(
                UUID.randomUUID(),
                "A retry-safe message"
        );

        ChatMessageResponse first = chatMessageService.send(guide, conversation.getId(), request);
        ChatMessageResponse retry = chatMessageService.send(guide, conversation.getId(), request);

        assertThat(retry.messageId()).isEqualTo(first.messageId());
        assertThat(messageRepository.findFirstPage(conversation.getId(), PageRequest.of(0, 10)))
                .hasSize(1);
        assertThatThrownBy(() -> chatMessageService.getMessages(
                outsider,
                conversation.getId(),
                null,
                20
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CHAT_NOT_FOUND));
    }

    private User createUser(String email, RoleType roleType) {
        Role role = roleRepository.findByName(roleType.name()).orElseThrow();
        User user = new User();
        user.setFirstName(roleType == RoleType.ROLE_GUIDE ? "Guide" : "Tourist");
        user.setLastName("Chat");
        user.setEmail(email);
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        return userRepository.saveAndFlush(user);
    }
}
