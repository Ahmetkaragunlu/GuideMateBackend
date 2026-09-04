package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatParticipantProfileUpdatedResponse;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.profile.service.UserAvatarUpdatedEvent;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChatParticipantProfileUpdatedEventListenerTest {

    @Mock
    private ChatConversationRepository conversationRepository;
    @Mock
    private SimpMessagingTemplate messagingTemplate;

    @Test
    void sendsAvatarUpdateOnlyToExistingConversationCounterparts() {
        User guide = user(7L);
        User tourist = user(42L);
        when(tourist.getUsername()).thenReturn("tourist@example.com");
        ChatConversation conversation = new ChatConversation(guide, tourist);
        when(conversationRepository.findAllForParticipant(7L))
                .thenReturn(List.of(conversation));
        var listener = new ChatParticipantProfileUpdatedEventListener(
                conversationRepository,
                messagingTemplate
        );

        listener.onUserAvatarUpdated(new UserAvatarUpdatedEvent(
                7L,
                "https://example.test/guide-avatar"
        ));

        verify(messagingTemplate).convertAndSendToUser(
                tourist.getUsername(),
                "/queue/chat-participant-updates",
                new ChatParticipantProfileUpdatedResponse(
                        7L,
                        "https://example.test/guide-avatar"
                )
        );
    }

    private User user(Long id) {
        User user = mock(User.class);
        when(user.getId()).thenReturn(id);
        return user;
    }
}
