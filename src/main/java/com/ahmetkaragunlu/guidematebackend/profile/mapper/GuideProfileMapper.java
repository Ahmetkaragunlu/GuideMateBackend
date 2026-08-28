package com.ahmetkaragunlu.guidematebackend.profile.mapper;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuidePerformanceSummary;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideProfileResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class GuideProfileMapper {

    private final MediaReferenceMapper mediaReferenceMapper;

    public GuideProfileResponse toResponse(
            User user,
            GuideProfile profile,
            GuidePerformanceSummary performance
    ) {
        String specialtyTitle = profile == null ? "" : profile.getSpecialtyTitle();
        String biography = profile == null ? "" : profile.getBiography();
        List<String> languageCodes = profile == null
                ? List.of()
                : profile.getLanguageCodes().stream().sorted().toList();
        MediaReferenceResponse avatar = mediaReferenceMapper.fromId(user.getAvatarMediaId());

        return new GuideProfileResponse(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.displayName(),
                specialtyTitle,
                biography,
                languageCodes,
                avatar,
                performance
        );
    }
}
