package com.ahmetkaragunlu.guidematebackend.chat.mapper;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessageDeliveryStatus;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatConversationResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatParticipantResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class ChatMapper {

    private final MediaReferenceMapper mediaReferenceMapper;

    public ChatConversationResponse toConversation(
            ChatConversation conversation,
            ChatMessage lastMessage,
            long unreadCount
    ) {
        Instant lastActivityAt = lastMessage == null
                ? conversation.getCreatedAt()
                : lastMessage.getSentAt();
        return new ChatConversationResponse(
                conversation.getId(),
                participant(conversation.getGuide()),
                participant(conversation.getTourist()),
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

    private ChatParticipantResponse participant(User user) {
        var avatar = mediaReferenceMapper.fromId(user.getAvatarMediaId());
        return new ChatParticipantResponse(
                user.getId(),
                user.displayName(),
                avatar == null ? null : avatar.imageUrl()
        );
    }
}
