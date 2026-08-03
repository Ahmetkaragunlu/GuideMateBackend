package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MediaAssetLifecycleService {

    private final MediaAssetRepository mediaAssetRepository;
    private final UserRepository userRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public MediaAsset createPending(
            Long ownerUserId,
            MediaPurpose purpose,
            String storageKey,
            ValidatedMedia validated
    ) {
        User owner = userRepository.getReferenceById(ownerUserId);
        MediaAsset media = MediaAsset.pending(
                owner,
                purpose,
                storageKey,
                validated.originalFileName(),
                validated.contentType(),
                validated.sizeBytes()
        );
        return mediaAssetRepository.save(media);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public MediaAsset markReady(UUID mediaAssetId) {
        MediaAsset media = mediaAssetRepository.findByIdForUpdate(mediaAssetId)
                .orElseThrow(() -> new BusinessException(ErrorCode.MEDIA_STORAGE_FAILED));
        media.markReady();
        return media;
    }
}
