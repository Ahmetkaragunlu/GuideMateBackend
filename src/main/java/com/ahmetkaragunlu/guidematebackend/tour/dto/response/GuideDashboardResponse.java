package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideLevel;

public record GuideDashboardResponse(
        long activeSessionCount,
        long pendingReviewCount,
        long completedSessionCount,
        long totalParticipantCount,
        double averageRating,
        long reviewCount,
        GuideLevel level,
        long currentMonthEarningsMinor,
        String currencyCode
) {
}
