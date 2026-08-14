package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.VersionPolicy;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.config.TourProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.CreateTourRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.GuideTourTab;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.SubmitTourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewType;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideTourCardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourReviewSubmissionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
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
public class GuideTourService {

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
    private final TourChangeRequestRepository changeRequestRepository;
    private final GuideProfileRepository guideProfileRepository;
    private final UserRepository userRepository;
    private final MediaService mediaService;
    private final TourContentFactory tourContentFactory;
    private final TourChangeSnapshotCodec snapshotCodec;
    private final TourSchedulePolicy schedulePolicy;
    private final TourLocationPolicy locationPolicy;
    private final VersionPolicy versionPolicy;
    private final TourMapper tourMapper;
    private final ReservationCapacityService capacityService;
    private final ReviewQueryService reviewQueryService;
    private final GuideEarningService guideEarningService;
    private final TourProperties tourProperties;
    private final Clock clock;

    @Transactional
    public TourReviewSubmissionResponse createTour(User currentUser, CreateTourRequest request) {
        GuideProfile profile = requireGuideProfile(currentUser.getId());
        Instant now = clock.instant();
        TourChangeSnapshot snapshot = tourContentFactory.fromRequest(request.tour());
        MediaAsset cover = mediaService.requireAssignableAsset(
                snapshot.coverMediaId(),
                currentUser.getId(),
                MediaPurpose.TOUR_COVER
        );
        schedulePolicy.validateNewSchedule(
                currentUser.getId(),
                request.session().startsAt(),
                request.session().durationMinutes(),
                now
        );

        Tour tour = Tour.submit(
                userRepository.getReferenceById(currentUser.getId()),
                snapshot,
                cover,
                now
        );
        tourRepository.save(tour);
        TourSession session = TourSession.create(
                tour,
                request.session().meetingPoint(),
                request.session().startsAt(),
                request.session().durationMinutes(),
                request.session().priceMinor(),
                tourProperties.currencyCode(),
                request.session().capacity(),
                TourSessionStatus.CLOSED
        );
        tourSessionRepository.save(session);

        TourDetailResponse detail = tourMapper.toDetail(
                tour,
                List.of(session),
                profile,
                Map.of(session.getId(), 0),
                ReviewAggregate.EMPTY
        );
        return new TourReviewSubmissionResponse(
                tour.getId(),
                AdminTourReviewType.NEW_TOUR,
                tour.getApprovalStatus().name(),
                detail
        );
    }

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
        return detail(tour);
    }

    @Transactional
    public TourReviewSubmissionResponse submitChange(
            User currentUser,
            UUID tourId,
            SubmitTourChangeRequest request
    ) {
        Tour tour = tourRepository.findOwnedByIdForUpdate(tourId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        versionPolicy.requireMatch(tour.getVersion(), request.baseVersion());
        if (tour.getApprovalStatus() == TourApprovalStatus.ARCHIVED
                || tour.getApprovalStatus() == TourApprovalStatus.PENDING_REVIEW) {
            throw new BusinessException(ErrorCode.TOUR_REVIEW_STATE_INVALID);
        }

        TourChangeSnapshot snapshot = tourContentFactory.fromRequest(request.proposedTour());
        MediaAsset proposedCover = mediaService.requireAssignableAsset(
                snapshot.coverMediaId(),
                currentUser.getId(),
                MediaPurpose.TOUR_COVER
        );
        Instant now = clock.instant();

        if (tour.getApprovalStatus() == TourApprovalStatus.REJECTED && tour.getPublishedAt() == null) {
            tour.resubmit(snapshot, proposedCover, now);
            closeManageableSessions(tour.getId());
            return new TourReviewSubmissionResponse(
                    tour.getId(),
                    AdminTourReviewType.NEW_TOUR,
                    tour.getApprovalStatus().name(),
                    detail(tour)
            );
        }

        if (tour.getApprovalStatus() != TourApprovalStatus.APPROVED) {
            throw new BusinessException(ErrorCode.TOUR_REVIEW_STATE_INVALID);
        }
        locationPolicy.requireUnchanged(tour, snapshot);
        if (changeRequestRepository.existsByTour_IdAndStatus(tourId, TourChangeRequestStatus.PENDING)) {
            throw new BusinessException(ErrorCode.TOUR_CHANGE_PENDING);
        }

        TourChangeRequest changeRequest = TourChangeRequest.submit(
                tour,
                request.baseVersion(),
                snapshotCodec.encode(snapshot),
                proposedCover,
                userRepository.getReferenceById(currentUser.getId()),
                now
        );
        changeRequestRepository.save(changeRequest);
        return new TourReviewSubmissionResponse(
                changeRequest.getId(),
                AdminTourReviewType.TOUR_CHANGE,
                changeRequest.getStatus().name(),
                detail(tour)
        );
    }

    @Transactional
    public TourDetailResponse archiveTour(User currentUser, UUID tourId) {
        Tour tour = tourRepository.findOwnedByIdForUpdate(tourId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        boolean archivable = tour.getApprovalStatus() == TourApprovalStatus.REJECTED
                && tour.getPublishedAt() == null
                && !changeRequestRepository.existsByTour_IdAndStatus(
                        tourId,
                        TourChangeRequestStatus.PENDING
                );
        if (!archivable) {
            throw new BusinessException(ErrorCode.TOUR_NOT_ARCHIVABLE);
        }
        tour.archive();
        closeManageableSessions(tourId);
        return detail(tour);
    }

    private TourDetailResponse detail(Tour tour) {
        List<TourSession> sessions = tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(tour.getId());
        GuideProfile profile = requireGuideProfile(tour.getGuide().getId());
        Map<UUID, Integer> occupiedCounts = capacityService.occupiedCounts(sessionIds(sessions));
        ReviewAggregate reviews = reviewQueryService.tourAggregates(List.of(tour.getId()))
                .getOrDefault(tour.getId(), ReviewAggregate.EMPTY);
        return tourMapper.toDetail(tour, sessions, profile, occupiedCounts, reviews);
    }

    private List<UUID> sessionIds(List<TourSession> sessions) {
        return sessions.stream().map(TourSession::getId).toList();
    }

    private List<UUID> tourIds(List<TourSession> sessions) {
        return sessions.stream().map(session -> session.getTour().getId()).distinct().toList();
    }

    private GuideProfile requireGuideProfile(Long guideId) {
        return guideProfileRepository.findByUserId(guideId)
                .orElseThrow(() -> new BusinessException(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
    }

    private void closeManageableSessions(UUID tourId) {
        tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(tourId).stream()
                .filter(session -> session.getStatus().isManageable())
                .forEach(TourSession::close);
    }

}
