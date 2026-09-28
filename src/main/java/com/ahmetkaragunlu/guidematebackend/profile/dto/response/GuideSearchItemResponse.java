package com.ahmetkaragunlu.guidematebackend.profile.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.response.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideLevel;

import java.util.List;

public record GuideSearchItemResponse(
        Long guideId,
        String displayName,
        String specialtyTitle,
        MediaReferenceResponse avatar,
        List<String> languageCodes,
        long completedSessionCount,
        long totalParticipantCount,
        double averageRating,
        long reviewCount,
        GuideLevel level
) {
}
