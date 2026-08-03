package com.ahmetkaragunlu.guidematebackend.profile.mapper;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideProfileResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class GuideProfileMapper {

    private final MediaUrlFactory mediaUrlFactory;

    public GuideProfileResponse toResponse(User user, GuideProfile profile) {
        String specialtyTitle = profile == null ? "" : profile.getSpecialtyTitle();
        String biography = profile == null ? "" : profile.getBiography();
        List<String> languageCodes = profile == null
                ? List.of()
                : profile.getLanguageCodes().stream().sorted().toList();
        MediaReferenceResponse avatar = profile == null ? null : toMediaReference(profile.getAvatar());

        return new GuideProfileResponse(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                displayName(user),
                specialtyTitle,
                biography,
                languageCodes,
                avatar
        );
    }

    private MediaReferenceResponse toMediaReference(MediaAsset media) {
        if (media == null) {
            return null;
        }
        return new MediaReferenceResponse(media.getId(), mediaUrlFactory.contentUrl(media.getId()));
    }

    private String displayName(User user) {
        return (user.getFirstName() + " " + user.getLastName()).trim();
    }
}
