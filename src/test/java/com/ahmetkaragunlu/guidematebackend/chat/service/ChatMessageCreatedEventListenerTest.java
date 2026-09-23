package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import org.junit.jupiter.api.Test;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ChatMessageCreatedEventListenerTest {

    @Test
    void publishesCommittedMessageToBothParticipantsPrivateQueues() {
        SimpMessagingTemplate messagingTemplate = mock(SimpMessagingTemplate.class);
        ChatMessageCreatedEventListener listener = new ChatMessageCreatedEventListener(messagingTemplate);
        ChatMessageResponse message = mock(ChatMessageResponse.class);

        listener.onMessageCreated(new ChatMessageCreatedEvent(
                message,
                "sender@example.com",
                "recipient@example.com"
        ));

        verify(messagingTemplate).convertAndSendToUser(
                "sender@example.com",
                "/queue/chat-messages",
                message
        );
        verify(messagingTemplate).convertAndSendToUser(
                "recipient@example.com",
                "/queue/chat-messages",
                message
        );
    }
}
