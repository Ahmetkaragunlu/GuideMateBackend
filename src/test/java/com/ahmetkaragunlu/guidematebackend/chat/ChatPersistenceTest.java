package com.ahmetkaragunlu.guidematebackend.chat;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatReadState;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ClearChatRequest;
import com.ahmetkaragunlu.guidematebackend.chat.dto.SendChatMessageRequest;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatMessageRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatReadStateRepository;
import com.ahmetkaragunlu.guidematebackend.chat.service.ChatConversationService;
import com.ahmetkaragunlu.guidematebackend.chat.service.ChatMessageService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationService;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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

    @Autowired
    private ChatConversationService chatConversationService;

    @Autowired
    private NotificationService notificationService;

    @Autowired
    private PlatformTransactionManager transactionManager;

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

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void sendsFirstMessageWhileConversationIsMarkedRead() throws Exception {
        ChatRaceFixture fixture = new TransactionTemplate(transactionManager).execute(status -> {
            String suffix = UUID.randomUUID().toString();
            User guide = createUser("guide-race-" + suffix + "@example.com", RoleType.ROLE_GUIDE);
            User tourist = createUser("tourist-race-" + suffix + "@example.com", RoleType.ROLE_TOURIST);
            ChatConversation conversation = conversationRepository.saveAndFlush(
                    new ChatConversation(guide, tourist)
            );
            Instant now = Instant.parse("2026-09-01T12:00:00Z");
            readStateRepository.saveAllAndFlush(List.of(
                    new ChatReadState(conversation, guide, now),
                    new ChatReadState(conversation, tourist, now)
            ));
            return new ChatRaceFixture(conversation.getId(), guide.getId(), tourist.getId());
        });
        User guide = userRepository.findById(fixture.guideId()).orElseThrow();
        SendChatMessageRequest request = new SendChatMessageRequest(
                UUID.randomUUID(),
                "First race-safe message"
        );

        runConcurrently(
                () -> {
                    chatMessageService.send(guide, fixture.conversationId(), request);
                    return null;
                },
                () -> {
                    chatConversationService.markRead(guide, fixture.conversationId());
                    return null;
                }
        );

        assertThat(messageRepository.findFirstPage(
                fixture.conversationId(),
                PageRequest.of(0, 10)
        )).hasSize(1);
        assertThat(messageRepository.countUnread(fixture.guideId())).isZero();
        assertThat(messageRepository.countUnread(fixture.touristId())).isEqualTo(1);
    }

    @Test
    void clearsHistoryOnlyForCurrentUserAndKeepsNewMessagesVisibleOnRetry() {
        User guide = createUser("guide-clear@example.com", RoleType.ROLE_GUIDE);
        User tourist = createUser("tourist-clear@example.com", RoleType.ROLE_TOURIST);
        User outsider = createUser("outsider-clear@example.com", RoleType.ROLE_TOURIST);
        ChatConversation conversation = conversationRepository.saveAndFlush(
                new ChatConversation(guide, tourist)
        );
        Instant now = Instant.parse("2026-09-04T08:00:00Z");
        readStateRepository.saveAllAndFlush(List.of(
                new ChatReadState(conversation, guide, now),
                new ChatReadState(conversation, tourist, now)
        ));
        chatMessageService.send(
                guide,
                conversation.getId(),
                new SendChatMessageRequest(UUID.randomUUID(), "Message before clear")
        );
        UUID clearRequestId = UUID.randomUUID();

        chatConversationService.clearConversation(
                tourist,
                conversation.getId(),
                new ClearChatRequest(clearRequestId)
        );

        assertThat(chatMessageService.getMessages(tourist, conversation.getId(), null, 20).content())
                .isEmpty();
        assertThat(chatConversationService.getConversations(tourist)).isEmpty();
        assertThat(chatMessageService.getMessages(guide, conversation.getId(), null, 20).content())
                .extracting(ChatMessageResponse::body)
                .containsExactly("Message before clear");
        assertThat(messageRepository.count()).isEqualTo(1);
        assertThat(notificationService.unreadCount(tourist).unreadCount()).isZero();
        assertThatThrownBy(() -> chatConversationService.clearConversation(
                outsider,
                conversation.getId(),
                new ClearChatRequest(UUID.randomUUID())
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CHAT_NOT_FOUND));

        chatMessageService.send(
                guide,
                conversation.getId(),
                new SendChatMessageRequest(UUID.randomUUID(), "Message after clear")
        );
        chatConversationService.clearConversation(
                tourist,
                conversation.getId(),
                new ClearChatRequest(clearRequestId)
        );

        assertThat(chatMessageService.getMessages(tourist, conversation.getId(), null, 20).content())
                .extracting(ChatMessageResponse::body)
                .containsExactly("Message after clear");
        assertThat(chatConversationService.getConversations(tourist))
                .singleElement()
                .satisfies(item -> assertThat(item.lastMessage().body()).isEqualTo("Message after clear"));
    }

    private <T> void runConcurrently(Callable<T> first, Callable<T> second) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<T> firstFuture = executor.submit(gated(first, ready, start));
            Future<T> secondFuture = executor.submit(gated(second, ready, start));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            firstFuture.get(10, TimeUnit.SECONDS);
            secondFuture.get(10, TimeUnit.SECONDS);
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private <T> Callable<T> gated(Callable<T> task, CountDownLatch ready, CountDownLatch start) {
        return () -> {
            ready.countDown();
            if (!start.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Concurrent test start timed out");
            }
            return task.call();
        };
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

    private record ChatRaceFixture(UUID conversationId, Long guideId, Long touristId) {
    }
}
