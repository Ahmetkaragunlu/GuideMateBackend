package com.ahmetkaragunlu.guidematebackend.profile.dto;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

import java.util.List;

public record GuideProfileResponse(
        Long guideId,
        String firstName,
        String lastName,
        String displayName,
        String specialtyTitle,
        String biography,
        List<String> languageCodes,
        MediaReferenceResponse avatar
) {
}
