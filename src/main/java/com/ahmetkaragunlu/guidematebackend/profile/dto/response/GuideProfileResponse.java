package com.ahmetkaragunlu.guidematebackend.profile.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuidePerformanceSummary;

import java.util.List;

public record GuideProfileResponse(
        Long guideId,
        String firstName,
        String lastName,
        String displayName,
        String specialtyTitle,
        String biography,
        List<String> languageCodes,
        MediaReferenceResponse avatar,
        GuidePerformanceSummary performance
) {
}
