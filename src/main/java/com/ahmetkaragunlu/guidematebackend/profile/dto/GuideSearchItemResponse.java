package com.ahmetkaragunlu.guidematebackend.profile.dto;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

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
