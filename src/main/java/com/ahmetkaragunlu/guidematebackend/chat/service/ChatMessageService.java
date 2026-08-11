package com.ahmetkaragunlu.guidematebackend.chat.service;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatMessage;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessagePageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.SendChatMessageRequest;
import com.ahmetkaragunlu.guidematebackend.chat.mapper.ChatMapper;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatConversationRepository;
import com.ahmetkaragunlu.guidematebackend.chat.repository.ChatMessageRepository;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ChatMessageService {

    private static final int MAX_BODY_LENGTH = 2000;
    private static final int NOTIFICATION_PREVIEW_LENGTH = 120;

    private final ChatConversationRepository conversationRepository;
    private final ChatMessageRepository messageRepository;
    private final UserRepository userRepository;
    private final NotificationPublisher notificationPublisher;
    private final ApplicationEventPublisher eventPublisher;
    private final ChatMapper chatMapper;
    private final Clock clock;

    @Transactional(readOnly = true)
    public ChatMessagePageResponse getMessages(
            User currentUser,
            UUID conversationId,
            UUID beforeMessageId,
            int size
    ) {
        conversationRepository.findParticipantConversation(conversationId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.CHAT_NOT_FOUND));

        List<ChatMessage> messages;
        if (beforeMessageId == null) {
            messages = messageRepository.findFirstPage(conversationId, PageRequest.of(0, size + 1));
        } else {
            ChatMessage cursor = messageRepository.findById(beforeMessageId)
                    .filter(message -> message.getConversation().getId().equals(conversationId))
                    .orElseThrow(() -> new BusinessException(ErrorCode.CHAT_MESSAGE_NOT_FOUND));
            messages = messageRepository.findPageBefore(
                    conversationId,
                    cursor.getSentAt(),
                    cursor.getId(),
                    PageRequest.of(0, size + 1)
            );
        }

        boolean hasNext = messages.size() > size;
        List<ChatMessage> page = new ArrayList<>(messages.subList(0, Math.min(size, messages.size())));
        UUID nextCursor = hasNext && !page.isEmpty() ? page.get(page.size() - 1).getId() : null;
        Collections.reverse(page);
        return new ChatMessagePageResponse(
                page.stream().map(chatMapper::toMessage).toList(),
                nextCursor,
                hasNext
        );
    }

    @Transactional
    public ChatMessageResponse send(
            User currentUser,
            UUID conversationId,
            SendChatMessageRequest request
    ) {
        User sender = userRepository.findByIdForUpdate(currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if (!sender.isEnabled()
                || sender.getTokenVersion() != currentUser.getTokenVersion()
                || sender.getRole() == null
                || (!RoleType.ROLE_GUIDE.name().equals(sender.getRole().getName())
                && !RoleType.ROLE_TOURIST.name().equals(sender.getRole().getName()))) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
        ChatConversation conversation = conversationRepository.findParticipantConversationForUpdate(
                        conversationId,
                        sender.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.CHAT_NOT_FOUND));
        String body = normalizeBody(request.body());

        ChatMessage duplicate = messageRepository.findBySender_IdAndClientMessageId(
                sender.getId(),
                request.clientMessageId()
        ).orElse(null);
        if (duplicate != null) {
            if (duplicate.getConversation().getId().equals(conversationId)
                    && duplicate.getBody().equals(body)) {
                return chatMapper.toMessage(duplicate);
            }
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }

        ChatMessage message = messageRepository.saveAndFlush(new ChatMessage(
                conversation,
                sender,
                request.clientMessageId(),
                body,
                clock.instant()
        ));
        User recipient = conversation.otherParticipant(sender.getId());
        ChatMessageResponse response = chatMapper.toMessage(message);
        notificationPublisher.publish(new NotificationCommand(
                recipient.getId(),
                NotificationType.CHAT_MESSAGE,
                sender.getId(),
                Map.of(
                        "chatId", conversation.getId().toString(),
                        "messageId", message.getId().toString(),
                        "senderId", sender.getId(),
                        "senderName", displayName(sender),
                        "messagePreview", preview(body)
                )
        ));
        eventPublisher.publishEvent(new ChatMessageCreatedEvent(
                response,
                sender.getUsername(),
                recipient.getUsername()
        ));
        return response;
    }

    private String normalizeBody(String value) {
        String body = value == null ? "" : value.trim();
        if (body.isEmpty()) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
        if (body.length() > MAX_BODY_LENGTH) {
            throw new BusinessException(ErrorCode.CHAT_MESSAGE_TOO_LONG);
        }
        return body;
    }

    private String preview(String body) {
        return body.length() <= NOTIFICATION_PREVIEW_LENGTH
                ? body
                : body.substring(0, NOTIFICATION_PREVIEW_LENGTH);
    }

    private String displayName(User user) {
        return (user.getFirstName() + " " + user.getLastName()).trim();
    }
}
