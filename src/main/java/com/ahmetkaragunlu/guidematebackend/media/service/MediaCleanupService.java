package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaStatus;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorage;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorageException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class MediaCleanupService {

    private static final List<MediaStatus> ORPHAN_CANDIDATE_STATUSES = List.of(
            MediaStatus.PENDING,
            MediaStatus.READY
    );

    private final MediaAssetRepository mediaAssetRepository;
    private final MediaStorage mediaStorage;
    private final MediaProperties mediaProperties;
    private final SchedulerProperties schedulerProperties;
    private final List<MediaReferencePolicy> referencePolicies;
    private final Clock clock;

    @Scheduled(fixedDelayString = "${media.cleanup-delay-ms:3600000}")
    @Transactional
    public void cleanupOrphans() {
        Instant cutoff = clock.instant().minus(mediaProperties.orphanGracePeriod());
        PageRequest batch = PageRequest.of(0, schedulerProperties.batchSize());
        List<MediaAsset> staleCandidates = mediaAssetRepository
                .findByStatusInAndCreatedAtBeforeOrderByCreatedAt(
                        ORPHAN_CANDIDATE_STATUSES,
                        cutoff,
                        batch
                );
        staleCandidates.forEach(media -> deleteIfUnreferenced(media.getId()));

        mediaAssetRepository.findByStatusOrderByCreatedAt(MediaStatus.DELETED, batch)
                .forEach(media -> deleteMarked(media.getId()));
    }

    private void deleteIfUnreferenced(UUID mediaAssetId) {
        mediaAssetRepository.findByIdForUpdate(mediaAssetId).ifPresent(media -> {
            if (!isReferenced(mediaAssetId)) {
                deleteCandidate(media);
            }
        });
    }

    private void deleteMarked(UUID mediaAssetId) {
        mediaAssetRepository.findByIdForUpdate(mediaAssetId).ifPresent(this::deleteCandidate);
    }

    private void deleteCandidate(MediaAsset media) {
        media.markDeleted();
        try {
            mediaStorage.delete(media.getStorageKey());
            mediaAssetRepository.delete(media);
        } catch (MediaStorageException exception) {
            log.warn("Media cleanup will retry asset {}", media.getId());
        }
    }

    private boolean isReferenced(UUID mediaAssetId) {
        return referencePolicies.stream().anyMatch(policy -> policy.isReferenced(mediaAssetId));
    }
}
