package com.ahmetkaragunlu.guidematebackend.chat.mapper;

import com.ahmetkaragunlu.guidematebackend.chat.domain.ChatConversation;
import com.ahmetkaragunlu.guidematebackend.chat.dto.ChatConversationResponse;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ChatMapperTest {

    private final MediaReferenceMapper mediaReferenceMapper = mock(MediaReferenceMapper.class);
    private final ChatMapper mapper = new ChatMapper(mediaReferenceMapper);

    @Test
    void mapsBothGuideAndTouristAvatarsFromUserIdentity() {
        UUID guideAvatarId = UUID.randomUUID();
        UUID touristAvatarId = UUID.randomUUID();
        User guide = user(1L, "Guide User", guideAvatarId);
        User tourist = user(2L, "Tourist User", touristAvatarId);
        ChatConversation conversation = mock(ChatConversation.class);
        when(conversation.getId()).thenReturn(UUID.randomUUID());
        when(conversation.getGuide()).thenReturn(guide);
        when(conversation.getTourist()).thenReturn(tourist);
        when(conversation.getCreatedAt()).thenReturn(Instant.parse("2026-08-27T10:00:00Z"));
        when(mediaReferenceMapper.fromId(guideAvatarId))
                .thenReturn(new MediaReferenceResponse(guideAvatarId, "https://example.test/guide"));
        when(mediaReferenceMapper.fromId(touristAvatarId))
                .thenReturn(new MediaReferenceResponse(touristAvatarId, "https://example.test/tourist"));

        ChatConversationResponse response = mapper.toConversation(conversation, null, 0L);

        assertThat(response.guide().avatarUrl()).isEqualTo("https://example.test/guide");
        assertThat(response.tourist().avatarUrl()).isEqualTo("https://example.test/tourist");
    }

    private User user(Long id, String displayName, UUID avatarMediaId) {
        User user = mock(User.class);
        when(user.getId()).thenReturn(id);
        when(user.displayName()).thenReturn(displayName);
        when(user.getAvatarMediaId()).thenReturn(avatarMediaId);
        return user;
    }
}
