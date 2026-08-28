package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserAvatarServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private MediaService mediaService;
    @Mock
    private MediaReferenceMapper mediaReferenceMapper;
    @Mock
    private MediaAsset mediaAsset;

    private UserAvatarService service;

    @BeforeEach
    void setUp() {
        service = new UserAvatarService(userRepository, mediaService, mediaReferenceMapper);
    }

    @Test
    void assignsOwnedReadyUserAvatarToLockedUser() {
        UUID mediaAssetId = UUID.randomUUID();
        User user = new User();
        MediaReferenceResponse expected = new MediaReferenceResponse(mediaAssetId, "https://example.test/avatar");
        when(userRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(user));
        when(mediaService.requireAssignableAsset(mediaAssetId, 42L, MediaPurpose.USER_AVATAR))
                .thenReturn(mediaAsset);
        when(mediaAsset.getId()).thenReturn(mediaAssetId);
        when(mediaReferenceMapper.from(mediaAsset)).thenReturn(expected);

        MediaReferenceResponse result = service.update(42L, mediaAssetId);

        assertThat(result).isEqualTo(expected);
        assertThat(user.getAvatarMediaId()).isEqualTo(mediaAssetId);
        verify(mediaService).requireAssignableAsset(mediaAssetId, 42L, MediaPurpose.USER_AVATAR);
    }
}
