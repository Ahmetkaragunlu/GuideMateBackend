package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.LanguageCodePolicy;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideProfileResponse;
import com.ahmetkaragunlu.guidematebackend.profile.dto.UpdateGuideProfileRequest;
import com.ahmetkaragunlu.guidematebackend.profile.mapper.GuideProfileMapper;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class GuideProfileService {

    private final GuideProfileRepository guideProfileRepository;
    private final UserRepository userRepository;
    private final MediaService mediaService;
    private final GuideProfileMapper guideProfileMapper;
    private final LanguageCodePolicy languageCodePolicy;

    @Transactional(readOnly = true)
    public GuideProfileResponse getOwnProfile(User currentUser) {
        GuideProfile profile = guideProfileRepository.findByUserId(currentUser.getId()).orElse(null);
        return guideProfileMapper.toResponse(currentUser, profile);
    }

    @Transactional(readOnly = true)
    public GuideProfileResponse getPublicProfile(Long guideId) {
        GuideProfile profile = guideProfileRepository.findByUserId(guideId)
                .filter(this::isPublicProfile)
                .orElseThrow(() -> new BusinessException(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
        return guideProfileMapper.toResponse(profile.getUser(), profile);
    }

    @Transactional
    public GuideProfileResponse updateProfile(User currentUser, UpdateGuideProfileRequest request) {
        Set<String> languageCodes = languageCodePolicy.normalize(request.languageCodes());
        GuideProfile profile = guideProfileRepository.findByUserId(currentUser.getId()).orElse(null);
        if (profile == null) {
            profile = GuideProfile.create(
                    userRepository.getReferenceById(currentUser.getId()),
                    request.specialtyTitle(),
                    request.biography(),
                    languageCodes
            );
        } else {
            profile.updateDetails(request.specialtyTitle(), request.biography(), languageCodes);
        }
        if (request.avatarMediaId() != null) {
            MediaAsset avatar = mediaService.requireAssignableAsset(
                    request.avatarMediaId(),
                    currentUser.getId(),
                    MediaPurpose.GUIDE_AVATAR
            );
            profile.updateAvatar(avatar);
        }

        GuideProfile savedProfile = guideProfileRepository.save(profile);
        return guideProfileMapper.toResponse(currentUser, savedProfile);
    }

    private boolean isPublicProfile(GuideProfile profile) {
        User user = profile.getUser();
        return user.getAccountStatus() == AccountStatus.ACTIVE
                && user.getRole() != null
                && RoleType.ROLE_GUIDE.name().equals(user.getRole().getName());
    }
}
