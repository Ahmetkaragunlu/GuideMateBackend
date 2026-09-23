package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.mapper.ChatMapper;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatMessageRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatReadStateRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChatConversationServiceTest {

    @Mock private ChatConversationRepository conversationRepository;
    @Mock private ChatMessageRepository messageRepository;
    @Mock private ChatReadStateRepository readStateRepository;
    @Mock private UserRepository userRepository;
    @Mock private NotificationService notificationService;
    @Mock private ChatMapper chatMapper;

    private ChatConversationService service;

    @BeforeEach
    void setUp() {
        service = new ChatConversationService(
                conversationRepository,
                messageRepository,
                readStateRepository,
                userRepository,
                notificationService,
                chatMapper,
                Clock.systemUTC()
        );
    }

    @Test
    void rejectsConversationWithSameUserBeforeDatabaseAccess() {
        User current = mock(User.class);
        when(current.getId()).thenReturn(7L);

        assertChatParticipantInvalid(() -> service.findOrCreate(current, 7L));
        verifyNoInteractions(userRepository, conversationRepository);
    }

    @Test
    void rejectsParticipantsWithSameRole() {
        User first = participant(RoleType.ROLE_TOURIST);
        User second = participant(RoleType.ROLE_TOURIST);
        when(first.getId()).thenReturn(1L);
        when(userRepository.findByIdForUpdate(1L)).thenReturn(Optional.of(first));
        when(userRepository.findByIdForUpdate(2L)).thenReturn(Optional.of(second));

        assertChatParticipantInvalid(() -> service.findOrCreate(first, 2L));
        verifyNoInteractions(conversationRepository);
    }

    @Test
    void rejectsInactiveParticipant() {
        User current = mock(User.class);
        User remote = mock(User.class);
        when(current.getId()).thenReturn(1L);
        when(current.getAccountStatus()).thenReturn(AccountStatus.ACTIVE);
        when(current.getRole()).thenReturn(mock(Role.class));
        when(remote.getAccountStatus()).thenReturn(AccountStatus.DISABLED);
        when(userRepository.findByIdForUpdate(1L)).thenReturn(Optional.of(current));
        when(userRepository.findByIdForUpdate(2L)).thenReturn(Optional.of(remote));

        assertChatParticipantInvalid(() -> service.findOrCreate(current, 2L));
        verifyNoInteractions(conversationRepository);
    }

    private User participant(RoleType roleType) {
        User user = mock(User.class);
        Role role = mock(Role.class);
        when(user.getAccountStatus()).thenReturn(AccountStatus.ACTIVE);
        when(user.getRole()).thenReturn(role);
        when(user.hasRole(any(RoleType.class))).thenAnswer(invocation -> invocation.getArgument(0) == roleType);
        return user;
    }

    private void assertChatParticipantInvalid(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action)
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CHAT_PARTICIPANT_INVALID));
    }
}
