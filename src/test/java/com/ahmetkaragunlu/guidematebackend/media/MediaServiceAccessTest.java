package com.ahmetkaragunlu.guidematebackend.media;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaAssetLifecycleService;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaFileValidator;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MediaServiceAccessTest {

    @Mock
    private MediaAssetRepository mediaAssetRepository;
    @Mock
    private MediaStorage mediaStorage;
    @Mock
    private MediaFileValidator mediaFileValidator;
    @Mock
    private MediaAssetLifecycleService mediaAssetLifecycleService;
    @Mock
    private MediaUrlFactory mediaUrlFactory;
    @Mock
    private MediaReferencePolicy referencePolicy;
    @Mock
    private MediaAsset mediaAsset;

    private MediaService mediaService;

    @BeforeEach
    void setUp() {
        mediaService = new MediaService(
                mediaAssetRepository,
                mediaStorage,
                mediaFileValidator,
                mediaAssetLifecycleService,
                mediaUrlFactory,
                List.of(referencePolicy)
        );
    }

    @Test
    void hidesPrivateMediaFromNonOwnerWithoutReadingStoredContent() {
        UUID mediaId = UUID.randomUUID();
        when(mediaAssetRepository.findById(mediaId)).thenReturn(Optional.of(mediaAsset));
        when(mediaAsset.isReady()).thenReturn(true);
        when(mediaAsset.isOwnedBy(99L)).thenReturn(false);
        when(referencePolicy.isPubliclyAccessible(mediaId)).thenReturn(false);
        when(referencePolicy.isAccessibleTo(mediaId, 99L)).thenReturn(false);

        assertThatThrownBy(() -> mediaService.getContent(mediaId, 99L))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MEDIA_NOT_FOUND));

        verify(mediaStorage, never()).load(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void hidesDeleteOperationFromNonOwner() {
        UUID mediaId = UUID.randomUUID();
        when(mediaAssetRepository.findByIdForUpdate(mediaId)).thenReturn(Optional.of(mediaAsset));
        when(mediaAsset.isOwnedBy(99L)).thenReturn(false);

        assertThatThrownBy(() -> mediaService.delete(mediaId, 99L))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MEDIA_NOT_FOUND));

        verify(mediaStorage, never()).delete(org.mockito.ArgumentMatchers.anyString());
    }
}
