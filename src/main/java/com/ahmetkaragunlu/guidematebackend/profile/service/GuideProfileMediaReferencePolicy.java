package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class GuideProfileMediaReferencePolicy implements MediaReferencePolicy {

    private final GuideProfileRepository guideProfileRepository;

    @Override
    public boolean isReferenced(UUID mediaAssetId) {
        return guideProfileRepository.existsByAvatar_Id(mediaAssetId);
    }

    @Override
    public boolean isPubliclyAccessible(UUID mediaAssetId) {
        return guideProfileRepository.existsPublicAvatarReference(
                mediaAssetId,
                AccountStatus.ACTIVE,
                RoleType.ROLE_GUIDE.name()
        );
    }
}
