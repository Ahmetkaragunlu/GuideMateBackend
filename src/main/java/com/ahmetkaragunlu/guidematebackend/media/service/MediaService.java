package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaStatus;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaDeletionResponse;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaUploadResponse;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorage;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorageException;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MediaService {

    private final MediaAssetRepository mediaAssetRepository;
    private final MediaStorage mediaStorage;
    private final MediaFileValidator mediaFileValidator;
    private final MediaAssetLifecycleService mediaAssetLifecycleService;
    private final MediaUrlFactory mediaUrlFactory;
    private final List<MediaReferencePolicy> referencePolicies;

    public MediaUploadResponse upload(MultipartFile file, MediaPurpose purpose, Long ownerUserId) {
        ValidatedMedia validated = mediaFileValidator.validate(file);
        String storageKey = UUID.randomUUID() + "." + validated.fileExtension();
        MediaAsset pendingMedia = mediaAssetLifecycleService.createPending(
                ownerUserId,
                purpose,
                storageKey,
                validated
        );

        try {
            mediaStorage.store(storageKey, file.getInputStream());
            MediaAsset readyMedia = mediaAssetLifecycleService.markReady(pendingMedia.getId());
            return toUploadResponse(readyMedia);
        } catch (IOException | MediaStorageException exception) {
            throw new BusinessException(ErrorCode.MEDIA_STORAGE_FAILED, exception);
        }
    }

    @Transactional(readOnly = true)
    public MediaContent getContent(UUID mediaAssetId, Long requesterUserId) {
        MediaAsset media = mediaAssetRepository.findById(mediaAssetId)
                .filter(MediaAsset::isReady)
                .orElseThrow(() -> new BusinessException(ErrorCode.MEDIA_NOT_FOUND));

        boolean publiclyAccessible = isPubliclyAccessible(mediaAssetId);
        boolean referenceAccessible = referencePolicies.stream()
                .anyMatch(policy -> policy.isAccessibleTo(mediaAssetId, requesterUserId));
        if (!publiclyAccessible && !referenceAccessible && !media.isOwnedBy(requesterUserId)) {
            throw new BusinessException(ErrorCode.MEDIA_NOT_FOUND);
        }

        try {
            Resource resource = mediaStorage.load(media.getStorageKey())
                    .orElseThrow(() -> new BusinessException(ErrorCode.MEDIA_NOT_FOUND));
            try (var input = resource.getInputStream()) {
                return new MediaContent(input.readAllBytes(), media.getContentType(), publiclyAccessible);
            }
        } catch (IOException | MediaStorageException exception) {
            throw new BusinessException(ErrorCode.MEDIA_STORAGE_FAILED, exception);
        }
    }

    @Transactional
    public MediaDeletionResponse delete(UUID mediaAssetId, Long ownerUserId) {
        MediaAsset media = mediaAssetRepository.findByIdForUpdate(mediaAssetId)
                .filter(asset -> asset.isOwnedBy(ownerUserId))
                .orElseThrow(() -> new BusinessException(ErrorCode.MEDIA_NOT_FOUND));
        if (isReferenced(mediaAssetId)) {
            throw new BusinessException(ErrorCode.MEDIA_IN_USE);
        }

        media.markDeleted();
        try {
            mediaStorage.delete(media.getStorageKey());
            mediaAssetRepository.delete(media);
            return new MediaDeletionResponse(mediaAssetId, MediaStatus.DELETED);
        } catch (MediaStorageException exception) {
            throw new BusinessException(ErrorCode.MEDIA_STORAGE_FAILED, exception);
        }
    }

    @Transactional
    public MediaAsset requireAssignableAsset(
            UUID mediaAssetId,
            Long ownerUserId,
            MediaPurpose expectedPurpose
    ) {
        MediaAsset media = mediaAssetRepository.findByIdForUpdate(mediaAssetId)
                .filter(MediaAsset::isReady)
                .filter(asset -> asset.isOwnedBy(ownerUserId))
                .orElseThrow(() -> new BusinessException(ErrorCode.MEDIA_NOT_FOUND));
        if (media.getPurpose() != expectedPurpose) {
            throw new BusinessException(ErrorCode.MEDIA_PURPOSE_MISMATCH);
        }
        return media;
    }

    private MediaUploadResponse toUploadResponse(MediaAsset media) {
        return new MediaUploadResponse(
                media.getId(),
                media.getPurpose(),
                media.getStatus(),
                mediaUrlFactory.contentUrl(media.getId()),
                media.getContentType(),
                media.getSizeBytes()
        );
    }

    private boolean isReferenced(UUID mediaAssetId) {
        return referencePolicies.stream().anyMatch(policy -> policy.isReferenced(mediaAssetId));
    }

    private boolean isPubliclyAccessible(UUID mediaAssetId) {
        return referencePolicies.stream().anyMatch(policy -> policy.isPubliclyAccessible(mediaAssetId));
    }
}
