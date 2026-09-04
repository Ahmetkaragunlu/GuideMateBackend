package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserAvatarService {

    private final UserRepository userRepository;
    private final MediaService mediaService;
    private final MediaReferenceMapper mediaReferenceMapper;
    private final ApplicationEventPublisher eventPublisher;

    @Transactional
    public MediaReferenceResponse update(Long userId, UUID avatarMediaId) {
        User user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        MediaAsset avatar = mediaService.requireAssignableAsset(
                avatarMediaId,
                userId,
                MediaPurpose.USER_AVATAR
        );
        user.updateAvatar(avatar.getId());
        MediaReferenceResponse response = mediaReferenceMapper.from(avatar);
        eventPublisher.publishEvent(new UserAvatarUpdatedEvent(userId, response.imageUrl()));
        return response;
    }
}
