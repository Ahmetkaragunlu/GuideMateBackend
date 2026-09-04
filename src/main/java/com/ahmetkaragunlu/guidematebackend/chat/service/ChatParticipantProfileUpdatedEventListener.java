package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatParticipantProfileUpdatedResponse;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.profile.service.UserAvatarUpdatedEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class ChatParticipantProfileUpdatedEventListener {

    private static final String PROFILE_UPDATE_DESTINATION = "/queue/chat-participant-updates";

    private final ChatConversationRepository conversationRepository;
    private final SimpMessagingTemplate messagingTemplate;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onUserAvatarUpdated(UserAvatarUpdatedEvent event) {
        ChatParticipantProfileUpdatedResponse response = new ChatParticipantProfileUpdatedResponse(
                event.userId(),
                event.avatarUrl()
        );
        conversationRepository.findAllForParticipant(event.userId()).stream()
                .map(conversation -> conversation.otherParticipant(event.userId()).getUsername())
                .distinct()
                .forEach(username -> messagingTemplate.convertAndSendToUser(
                        username,
                        PROFILE_UPDATE_DESTINATION,
                        response
                ));
    }
}
