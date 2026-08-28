package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class UserAvatarMediaReferencePolicy implements MediaReferencePolicy {

    private final UserRepository userRepository;

    @Override
    public boolean isReferenced(UUID mediaAssetId) {
        return userRepository.existsByAvatarMediaId(mediaAssetId);
    }

    @Override
    public boolean isPubliclyAccessible(UUID mediaAssetId) {
        return userRepository.existsActiveAvatarReference(mediaAssetId, AccountStatus.ACTIVE);
    }
}
