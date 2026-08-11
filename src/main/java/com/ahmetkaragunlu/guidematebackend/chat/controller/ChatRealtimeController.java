package com.ahmetkaragunlu.guidematebackend.chat.controller;

import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatRealtimeErrorResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.SendChatMessageRequest;
import com.ahmetkaragunlu.guidematebackend.chat.service.ChatMessageService;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageExceptionHandler;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.support.MethodArgumentNotValidException;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;

import java.util.UUID;

@Controller
@RequiredArgsConstructor
public class ChatRealtimeController {

    private final ChatMessageService messageService;

    @MessageMapping("/chats/{chatId}/messages")
    public void send(
            Authentication authentication,
            @DestinationVariable UUID chatId,
            @Valid @Payload SendChatMessageRequest request
    ) {
        messageService.send((User) authentication.getPrincipal(), chatId, request);
    }

    @MessageExceptionHandler(BusinessException.class)
    @SendToUser("/queue/chat-errors")
    public ChatRealtimeErrorResponse handleBusinessException(BusinessException exception) {
        return new ChatRealtimeErrorResponse(exception.getErrorCode());
    }

    @MessageExceptionHandler(MethodArgumentNotValidException.class)
    @SendToUser("/queue/chat-errors")
    public ChatRealtimeErrorResponse handleValidationException(MethodArgumentNotValidException exception) {
        return new ChatRealtimeErrorResponse(ErrorCode.VALIDATION_FAILED);
    }
}
