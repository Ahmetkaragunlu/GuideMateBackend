package com.ahmetkaragunlu.guidematebackend.profile.domain;

public record GuidePerformanceSummary(
        long completedSessionCount,
        long totalParticipantCount,
        double averageRating,
        long reviewCount,
        GuideLevel level
) {
}
