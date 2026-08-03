package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.tour.config.TourProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideDashboardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideLevel;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
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
    private final TourProperties tourProperties;
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
        long completedSessionCount = tourSessionRepository.countByTour_Guide_IdAndStatus(
                guideId,
                TourSessionStatus.COMPLETED
        );

        return new GuideDashboardResponse(
                activeSessionCount,
                pendingReviewCount,
                completedSessionCount,
                0,
                0.0,
                0,
                GuideLevel.APPROVED,
                0,
                tourProperties.currencyCode()
        );
    }
}
