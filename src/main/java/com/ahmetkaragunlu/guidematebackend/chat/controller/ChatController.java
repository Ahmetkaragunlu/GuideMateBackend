package com.ahmetkaragunlu.guidematebackend.chat.controller;

import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatConversationResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessagePageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatMessageResponse;
import com.ahmetkaragunlu.guidematebackend.chat.dto.SendChatMessageRequest;
import com.ahmetkaragunlu.guidematebackend.chat.service.ChatConversationService;
import com.ahmetkaragunlu.guidematebackend.chat.service.ChatMessageService;
import com.ahmetkaragunlu.guidematebackend.common.config.OpenApiConfig;
import com.ahmetkaragunlu.guidematebackend.common.dto.UnreadCountResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@Validated
@Tag(name = "Chats")
@RestController
@RequestMapping("/api/v1/chats")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
@RequiredArgsConstructor
public class ChatController {

    private final ChatConversationService conversationService;
    private final ChatMessageService messageService;

    @Operation(summary = "Find or create the guide-tourist conversation with a user")
    @PostMapping("/with-user/{remoteUserId}")
    public ResponseEntity<ChatConversationResponse> findOrCreate(
            @AuthenticationPrincipal User currentUser,
            @PathVariable Long remoteUserId
    ) {
        return ResponseEntity.ok(conversationService.findOrCreate(currentUser, remoteUserId));
    }

    @Operation(summary = "List the current user's conversations with last message and unread count")
    @GetMapping
    public ResponseEntity<List<ChatConversationResponse>> getConversations(
            @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(conversationService.getConversations(currentUser));
    }

    @Operation(summary = "Get cursor-paginated message history for an owned conversation")
    @GetMapping("/{chatId}/messages")
    public ResponseEntity<ChatMessagePageResponse> getMessages(
            @AuthenticationPrincipal User currentUser,
            @PathVariable UUID chatId,
            @RequestParam(required = false) UUID before,
            @RequestParam(defaultValue = "50") @Min(1) @Max(100) int size
    ) {
        return ResponseEntity.ok(messageService.getMessages(currentUser, chatId, before, size));
    }

    @Operation(summary = "Send a message through the REST fallback path")
    @PostMapping("/{chatId}/messages")
    public ResponseEntity<ChatMessageResponse> send(
            @AuthenticationPrincipal User currentUser,
            @PathVariable UUID chatId,
            @Valid @RequestBody SendChatMessageRequest request
    ) {
        return ResponseEntity.ok(messageService.send(currentUser, chatId, request));
    }

    @Operation(summary = "Mark the current user's conversation as read")
    @PostMapping("/{chatId}/read")
    public ResponseEntity<UnreadCountResponse> markRead(
            @AuthenticationPrincipal User currentUser,
            @PathVariable UUID chatId
    ) {
        return ResponseEntity.ok(conversationService.markRead(currentUser, chatId));
    }

    @Operation(summary = "Get the current user's total chat unread count")
    @GetMapping("/unread-count")
    public ResponseEntity<UnreadCountResponse> unreadCount(@AuthenticationPrincipal User currentUser) {
        return ResponseEntity.ok(conversationService.unreadCount(currentUser));
    }
}
