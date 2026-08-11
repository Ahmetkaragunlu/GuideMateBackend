package com.ahmetkaragunlu.guidematebackend.chat;

import com.ahmetkaragunlu.guidematebackend.chat.config.StompJwtChannelInterceptor;
import com.ahmetkaragunlu.guidematebackend.common.security.JwtService;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StompJwtChannelInterceptorTest {

    private final JwtService jwtService = mock(JwtService.class);
    private final UserDetailsService userDetailsService = mock(UserDetailsService.class);
    private final StompJwtChannelInterceptor interceptor = new StompJwtChannelInterceptor(
            jwtService,
            userDetailsService
    );

    @Test
    void authenticatesConnectFrameWithValidJwt() {
        User user = activeUser("guide@example.com");
        when(jwtService.extractUsername("valid-token")).thenReturn(user.getUsername());
        when(userDetailsService.loadUserByUsername(user.getUsername())).thenReturn(user);
        when(jwtService.isTokenValid("valid-token", user)).thenReturn(true);
        StompHeaderAccessor accessor = StompHeaderAccessor.create(StompCommand.CONNECT);
        accessor.setNativeHeader("Authorization", "Bearer valid-token");

        Message<?> result = interceptor.preSend(message(accessor), mock(org.springframework.messaging.MessageChannel.class));

        StompHeaderAccessor resultAccessor = StompHeaderAccessor.wrap(result);
        assertThat(resultAccessor.getUser()).isNotNull();
        assertThat(resultAccessor.getUser().getName()).isEqualTo(user.getUsername());
    }

    @Test
    void allowsOnlyPrivateUserQueueSubscriptions() {
        User user = activeUser("tourist@example.com");
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user,
                null,
                user.getAuthorities()
        );
        StompHeaderAccessor allowed = StompHeaderAccessor.create(StompCommand.SUBSCRIBE);
        allowed.setUser(authentication);
        allowed.setDestination("/user/queue/chat-messages");
        StompHeaderAccessor forbidden = StompHeaderAccessor.create(StompCommand.SUBSCRIBE);
        forbidden.setUser(authentication);
        forbidden.setDestination("/topic/chats/any-id");

        assertThat(interceptor.preSend(message(allowed), mock(org.springframework.messaging.MessageChannel.class)))
                .isNotNull();
        assertThatThrownBy(() -> interceptor.preSend(
                message(forbidden),
                mock(org.springframework.messaging.MessageChannel.class)
        )).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    @Test
    void rejectsSendFramesThatBypassTheApplicationMessageHandler() {
        User user = activeUser("sender@example.com");
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user,
                null,
                user.getAuthorities()
        );
        StompHeaderAccessor allowed = StompHeaderAccessor.create(StompCommand.SEND);
        allowed.setUser(authentication);
        allowed.setDestination("/app/chats/2d9209d7-4c89-47b0-a4c5-e691701757b8/messages");
        StompHeaderAccessor forbidden = StompHeaderAccessor.create(StompCommand.SEND);
        forbidden.setUser(authentication);
        forbidden.setDestination("/queue/chat-messages");

        assertThat(interceptor.preSend(message(allowed), mock(org.springframework.messaging.MessageChannel.class)))
                .isNotNull();
        assertThatThrownBy(() -> interceptor.preSend(
                message(forbidden),
                mock(org.springframework.messaging.MessageChannel.class)
        )).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    private Message<byte[]> message(StompHeaderAccessor accessor) {
        accessor.setLeaveMutable(true);
        return MessageBuilder.createMessage(new byte[0], accessor.getMessageHeaders());
    }

    private User activeUser(String email) {
        User user = new User();
        user.setEmail(email);
        user.setPassword("not-used");
        user.setAccountStatus(AccountStatus.ACTIVE);
        return user;
    }
}
