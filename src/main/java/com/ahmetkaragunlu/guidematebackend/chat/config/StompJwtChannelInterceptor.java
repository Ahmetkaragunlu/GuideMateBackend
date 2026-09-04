package com.ahmetkaragunlu.guidematebackend.chat.config;

import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class StompJwtChannelInterceptor implements ChannelInterceptor {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final Set<String> ALLOWED_SUBSCRIPTIONS = Set.of(
            "/user/queue/chat-messages",
            "/user/queue/chat-participant-updates",
            "/user/queue/chat-errors",
            "/user/queue/notifications"
    );
    private static final Pattern ALLOWED_SEND_DESTINATION = Pattern.compile(
            "^/app/chats/[0-9a-fA-F-]{36}/messages$"
    );

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
        if (accessor.getCommand() == StompCommand.CONNECT) {
            accessor.setUser(authenticate(accessor));
        } else if (accessor.getCommand() == StompCommand.SEND
                || accessor.getCommand() == StompCommand.SUBSCRIBE) {
            requireAuthenticated(accessor);
        }
        if (accessor.getCommand() == StompCommand.SUBSCRIBE
                && !ALLOWED_SUBSCRIPTIONS.contains(accessor.getDestination())) {
            throw new AuthenticationCredentialsNotFoundException("STOMP subscription is not allowed");
        }
        if (accessor.getCommand() == StompCommand.SEND
                && (accessor.getDestination() == null
                || !ALLOWED_SEND_DESTINATION.matcher(accessor.getDestination()).matches())) {
            throw new AuthenticationCredentialsNotFoundException("STOMP send destination is not allowed");
        }
        return MessageBuilder.createMessage(message.getPayload(), accessor.getMessageHeaders());
    }

    private UsernamePasswordAuthenticationToken authenticate(StompHeaderAccessor accessor) {
        String authorization = accessor.getFirstNativeHeader("Authorization");
        if (authorization == null) {
            authorization = accessor.getFirstNativeHeader("authorization");
        }
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            throw new AuthenticationCredentialsNotFoundException("STOMP JWT is required");
        }
        String token = authorization.substring(BEARER_PREFIX.length());
        try {
            String username = jwtService.extractUsername(token);
            User user = (User) userDetailsService.loadUserByUsername(username);
            if (!jwtService.isTokenValid(token, user)) {
                throw new AuthenticationCredentialsNotFoundException("STOMP JWT is invalid");
            }
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        } catch (JwtException | AuthenticationException | IllegalArgumentException exception) {
            throw new AuthenticationCredentialsNotFoundException("STOMP JWT is invalid", exception);
        }
    }

    private void requireAuthenticated(StompHeaderAccessor accessor) {
        if (accessor.getUser() == null) {
            throw new AuthenticationCredentialsNotFoundException("Authenticated STOMP session is required");
        }
    }
}
