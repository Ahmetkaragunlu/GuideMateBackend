package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.GuideTourTab;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideTourCardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class GuideTourQueryService {

    private static final List<TourSessionStatus> MANAGEABLE_SESSION_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );
    private static final List<TourApprovalStatus> REVIEW_TOUR_STATUSES = List.of(
            TourApprovalStatus.PENDING_REVIEW,
            TourApprovalStatus.REJECTED
    );
    private static final List<TourSessionStatus> TERMINAL_SESSION_STATUSES = List.of(
            TourSessionStatus.COMPLETED,
            TourSessionStatus.CANCELLED
    );

    private final TourRepository tourRepository;
    private final TourSessionRepository tourSessionRepository;
    private final TourMapper tourMapper;
    private final ReservationCapacityService capacityService;
    private final ReviewQueryService reviewQueryService;
    private final TourDetailQueryService tourDetailQueryService;
    private final GuideEarningService guideEarningService;
    private final Clock clock;

    @Transactional(readOnly = true)
    public PageResponse<GuideTourCardResponse> getGuideTours(
            User currentUser,
            GuideTourTab tab,
            int page,
            int size
    ) {
        PageRequest pageRequest = PageRequest.of(page, size);
        Instant now = clock.instant();
        Page<TourSession> sessions = switch (tab) {
            case ACTIVE -> tourSessionRepository.findActiveGuideSessions(
                    currentUser.getId(),
                    TourApprovalStatus.APPROVED,
                    MANAGEABLE_SESSION_STATUSES,
                    now,
                    pageRequest
            );
            case REVIEW -> tourSessionRepository.findGuideReviewSessions(
                    currentUser.getId(),
                    REVIEW_TOUR_STATUSES,
                    TourChangeRequestStatus.PENDING,
                    MANAGEABLE_SESSION_STATUSES,
                    pageRequest
            );
            case PAST -> tourSessionRepository.findPastGuideSessions(
                    currentUser.getId(),
                    TERMINAL_SESSION_STATUSES,
                    pageRequest
            );
        };
        List<TourSession> content = sessions.getContent();
        Map<UUID, Integer> occupiedCounts = capacityService.occupiedCounts(sessionIds(content));
        Map<UUID, ReviewAggregate> reviews = reviewQueryService.tourAggregates(tourIds(content));
        Map<UUID, Long> earnings = guideEarningService.sessionNetEarnings(sessionIds(content));
        return PageResponse.from(sessions.map(session -> tourMapper.toGuideCard(
                session,
                occupiedCounts.getOrDefault(session.getId(), 0),
                reviews.getOrDefault(session.getTour().getId(), ReviewAggregate.EMPTY),
                session.getStatus() == TourSessionStatus.CANCELLED ? null : earnings.get(session.getId())
        )));
    }

    @Transactional(readOnly = true)
    public TourDetailResponse getOwnedTour(User currentUser, UUID tourId) {
        Tour tour = tourRepository.findOwnedDetails(tourId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        return tourDetailQueryService.getDetail(tour);
    }

    private List<UUID> sessionIds(List<TourSession> sessions) {
        return sessions.stream().map(TourSession::getId).toList();
    }

    private List<UUID> tourIds(List<TourSession> sessions) {
        return sessions.stream().map(session -> session.getTour().getId()).distinct().toList();
    }
}
