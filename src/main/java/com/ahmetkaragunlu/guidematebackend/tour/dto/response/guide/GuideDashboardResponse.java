package com.ahmetkaragunlu.guidematebackend.tour.dto.response.guide;

import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideLevel;

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
