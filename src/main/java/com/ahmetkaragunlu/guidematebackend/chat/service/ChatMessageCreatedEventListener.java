package com.ahmetkaragunlu.guidematebackend.chat.service;

import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class ChatMessageCreatedEventListener {

    private static final String MESSAGE_DESTINATION = "/queue/chat-messages";

    private final SimpMessagingTemplate messagingTemplate;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onMessageCreated(ChatMessageCreatedEvent event) {
        messagingTemplate.convertAndSendToUser(
                event.senderUsername(),
                MESSAGE_DESTINATION,
                event.message()
        );
        messagingTemplate.convertAndSendToUser(
                event.recipientUsername(),
                MESSAGE_DESTINATION,
                event.message()
        );
    }
}
