package com.ahmetkaragunlu.guidematebackend.media;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaAssetLifecycleService;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaFileValidator;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaImageProcessor;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.media.service.ProcessedMedia;
import com.ahmetkaragunlu.guidematebackend.media.service.ValidatedMedia;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
    private MediaImageProcessor mediaImageProcessor;
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
                mediaImageProcessor,
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

    @Test
    void storesProcessedContentAndItsCanonicalMetadata() throws Exception {
        byte[] uploaded = "uploaded".getBytes(StandardCharsets.UTF_8);
        byte[] processed = "processed".getBytes(StandardCharsets.UTF_8);
        MockMultipartFile file = new MockMultipartFile("file", "avatar.webp", "image/webp", uploaded);
        ValidatedMedia validated = new ValidatedMedia("image/webp", "webp", "avatar.webp", uploaded.length);
        ValidatedMedia canonical = new ValidatedMedia("image/png", "png", "avatar.png", processed.length);
        UUID mediaId = UUID.randomUUID();
        when(mediaFileValidator.validate(file)).thenReturn(validated);
        when(mediaImageProcessor.process(file, validated)).thenReturn(new ProcessedMedia(processed, canonical));
        when(mediaAssetLifecycleService.createPending(eq(7L), eq(MediaPurpose.USER_AVATAR), any(), eq(canonical)))
                .thenReturn(mediaAsset);
        when(mediaAsset.getId()).thenReturn(mediaId);
        when(mediaAssetLifecycleService.markReady(mediaId)).thenReturn(mediaAsset);

        mediaService.upload(file, MediaPurpose.USER_AVATAR, 7L);

        ArgumentCaptor<String> storageKey = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<InputStream> content = ArgumentCaptor.forClass(InputStream.class);
        verify(mediaStorage).store(storageKey.capture(), content.capture());
        assertThat(storageKey.getValue()).endsWith(".png");
        assertThat(content.getValue().readAllBytes()).isEqualTo(processed);
    }
}
