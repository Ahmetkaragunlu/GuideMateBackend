package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.tour.config.TourProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideDashboardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuidePerformanceSummary;
import com.ahmetkaragunlu.guidematebackend.profile.service.GuidePerformanceService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

@Service
@RequiredArgsConstructor
public class GuideDashboardService {

    private final TourRepository tourRepository;
    private final TourSessionRepository tourSessionRepository;
    private final TourChangeRequestRepository changeRequestRepository;
    private final GuidePerformanceService guidePerformanceService;
    private final TourProperties tourProperties;
    private final GuideEarningService guideEarningService;
    private final Clock clock;

    @Transactional(readOnly = true)
    public GuideDashboardResponse getDashboard(User currentUser) {
        Long guideId = currentUser.getId();
        long activeSessionCount = tourSessionRepository.countActiveSessions(
                guideId,
                TourApprovalStatus.APPROVED,
                TourSessionStatus.OPEN_FOR_BOOKING,
                clock.instant()
        );
        long pendingReviewCount = tourRepository.countByGuide_IdAndApprovalStatus(
                guideId,
                TourApprovalStatus.PENDING_REVIEW
        ) + changeRequestRepository.countByTour_Guide_IdAndStatus(
                guideId,
                TourChangeRequestStatus.PENDING
        );
        GuidePerformanceSummary performance = guidePerformanceService.get(guideId);

        return new GuideDashboardResponse(
                activeSessionCount,
                pendingReviewCount,
                performance.completedSessionCount(),
                performance.totalParticipantCount(),
                performance.averageRating(),
                performance.reviewCount(),
                performance.level(),
                guideEarningService.currentMonthNet(guideId),
                tourProperties.currencyCode()
        );
    }
}
