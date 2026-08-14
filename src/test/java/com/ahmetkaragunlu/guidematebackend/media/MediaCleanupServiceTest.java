package com.ahmetkaragunlu.guidematebackend.media;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaStatus;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaCleanupService;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.util.unit.DataSize;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MediaCleanupServiceTest {

    @Mock
    private MediaAssetRepository mediaAssetRepository;
    @Mock
    private MediaStorage mediaStorage;
    @Mock
    private MediaReferencePolicy referencePolicy;

    private MediaCleanupService service;

    @BeforeEach
    void setUp() {
        service = new MediaCleanupService(
                mediaAssetRepository,
                mediaStorage,
                new MediaProperties(Path.of("build/test-media"), DataSize.ofMegabytes(5), Duration.ofHours(24)),
                schedulerProperties(),
                List.of(referencePolicy),
                Clock.fixed(Instant.parse("2026-08-13T00:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void deletesOnlyUnreferencedStaleMedia() {
        UUID referencedId = UUID.randomUUID();
        UUID orphanId = UUID.randomUUID();
        MediaAsset referenced = org.mockito.Mockito.mock(MediaAsset.class);
        MediaAsset orphan = org.mockito.Mockito.mock(MediaAsset.class);

        when(referenced.getId()).thenReturn(referencedId);
        when(orphan.getId()).thenReturn(orphanId);
        when(orphan.getStorageKey()).thenReturn("orphan.png");
        when(mediaAssetRepository.findByStatusInAndCreatedAtBeforeOrderByCreatedAt(
                anyCollection(),
                any(Instant.class),
                any(Pageable.class)
        )).thenReturn(List.of(referenced, orphan));
        when(mediaAssetRepository.findByStatusOrderByCreatedAt(
                org.mockito.ArgumentMatchers.eq(MediaStatus.DELETED),
                any(Pageable.class)
        )).thenReturn(List.of());
        when(mediaAssetRepository.findByIdForUpdate(referencedId)).thenReturn(Optional.of(referenced));
        when(mediaAssetRepository.findByIdForUpdate(orphanId)).thenReturn(Optional.of(orphan));
        when(referencePolicy.isReferenced(referencedId)).thenReturn(true);
        when(referencePolicy.isReferenced(orphanId)).thenReturn(false);

        service.cleanupOrphans();

        verify(referenced, never()).markDeleted();
        verify(mediaStorage, never()).delete(referenced.getStorageKey());
        verify(mediaAssetRepository, never()).delete(referenced);
        verify(orphan).markDeleted();
        verify(mediaStorage).delete("orphan.png");
        verify(mediaAssetRepository).delete(orphan);
    }

    private SchedulerProperties schedulerProperties() {
        return new SchedulerProperties(
                50,
                Duration.ofMinutes(1),
                5,
                Duration.ofMinutes(1),
                5,
                Duration.ofMinutes(5),
                Duration.ofMinutes(1),
                5,
                Duration.ofHours(24),
                Duration.ofDays(30),
                Duration.ofDays(90)
        );
    }
}
