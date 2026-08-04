package com.ahmetkaragunlu.guidematebackend.profile.dto;

public record GuidePerformanceSummary(
        long completedSessionCount,
        long totalParticipantCount,
        double averageRating,
        long reviewCount,
        GuideLevel level
) {
}
