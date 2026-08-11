package com.ahmetkaragunlu.guidematebackend.chat.mapper;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessageDeliveryStatus;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatConversationResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatParticipantResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class ChatMapper {

    private final MediaUrlFactory mediaUrlFactory;

    public ChatConversationResponse toConversation(
            ChatConversation conversation,
            ChatMessage lastMessage,
            long unreadCount,
            GuideProfile guideProfile
    ) {
        Instant lastActivityAt = lastMessage == null
                ? conversation.getCreatedAt()
                : lastMessage.getSentAt();
        return new ChatConversationResponse(
                conversation.getId(),
                participant(conversation.getGuide(), guideProfile),
                participant(conversation.getTourist(), null),
                lastMessage == null ? null : toMessage(lastMessage),
                unreadCount,
                conversation.getCreatedAt(),
                lastActivityAt
        );
    }

    public ChatMessageResponse toMessage(ChatMessage message) {
        return new ChatMessageResponse(
                message.getId(),
                message.getConversation().getId(),
                message.getSender().getId(),
                message.getClientMessageId(),
                message.getBody(),
                message.getSentAt(),
                ChatMessageDeliveryStatus.SENT
        );
    }

    private ChatParticipantResponse participant(User user, GuideProfile guideProfile) {
        String avatarUrl = guideProfile == null || guideProfile.getAvatar() == null
                ? null
                : mediaUrlFactory.contentUrl(guideProfile.getAvatar().getId());
        return new ChatParticipantResponse(
                user.getId(),
                (user.getFirstName() + " " + user.getLastName()).trim(),
                avatarUrl
        );
    }
}
