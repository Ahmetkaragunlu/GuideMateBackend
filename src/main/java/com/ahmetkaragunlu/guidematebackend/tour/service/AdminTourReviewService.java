package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewDecisionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewSummaryResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewType;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourProposalResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AdminTourReviewService {

    private final TourRepository tourRepository;
    private final TourSessionRepository tourSessionRepository;
    private final TourChangeRequestRepository changeRequestRepository;
    private final GuideProfileRepository guideProfileRepository;
    private final UserRepository userRepository;
    private final MediaService mediaService;
    private final TourContentFactory tourContentFactory;
    private final TourChangeSnapshotCodec snapshotCodec;
    private final TourMapper tourMapper;
    private final ReservationCapacityService capacityService;
    private final ReviewQueryService reviewQueryService;
    private final Clock clock;

    @Transactional(readOnly = true)
    public PageResponse<AdminTourReviewSummaryResponse> getPendingReviews(int page, int size) {
        List<AdminTourReviewSummaryResponse> reviews = new ArrayList<>();
        tourRepository.findAllByApprovalStatusOrderBySubmittedAtDesc(TourApprovalStatus.PENDING_REVIEW)
                .stream()
                .map(this::toNewTourSummary)
                .forEach(reviews::add);
        changeRequestRepository.findAllByStatusOrderBySubmittedAtDesc(TourChangeRequestStatus.PENDING)
                .stream()
                .map(this::toChangeSummary)
                .forEach(reviews::add);
        reviews.sort(Comparator
                .comparing(AdminTourReviewSummaryResponse::submittedAt).reversed()
                .thenComparing(AdminTourReviewSummaryResponse::reviewId));

        int from = Math.min(page * size, reviews.size());
        int to = Math.min(from + size, reviews.size());
        int totalPages = reviews.isEmpty() ? 0 : (reviews.size() + size - 1) / size;
        return new PageResponse<>(
                reviews.subList(from, to),
                page,
                size,
                reviews.size(),
                totalPages,
                page == 0,
                page >= Math.max(totalPages - 1, 0)
        );
    }

    @Transactional(readOnly = true)
    public AdminTourReviewDetailResponse getReview(UUID reviewId) {
        TourChangeRequest changeRequest = changeRequestRepository.findDetailsById(reviewId).orElse(null);
        if (changeRequest != null) {
            return changeDetail(changeRequest);
        }
        Tour tour = tourRepository.findDetailsById(reviewId)
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_REVIEW_NOT_FOUND));
        return newTourDetail(tour);
    }

    @Transactional
    public AdminTourReviewDecisionResponse approve(User currentAdmin, UUID reviewId) {
        Instant now = clock.instant();
        User reviewer = userRepository.getReferenceById(currentAdmin.getId());
        TourChangeRequest changeRequest = changeRequestRepository.findByIdForUpdate(reviewId).orElse(null);
        if (changeRequest != null) {
            requirePending(changeRequest);
            Tour tour = tourRepository.findByIdForUpdate(changeRequest.getTour().getId())
                    .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
            if (tour.getApprovalStatus() != TourApprovalStatus.APPROVED) {
                throw new BusinessException(ErrorCode.TOUR_REVIEW_STATE_INVALID);
            }
            if (tour.getVersion() != changeRequest.getBaseVersion()) {
                throw new BusinessException(ErrorCode.CONCURRENT_UPDATE);
            }
            TourChangeSnapshot snapshot = tourContentFactory.validate(
                    snapshotCodec.decode(changeRequest.getProposedSnapshot())
            );
            requireLocationUnchanged(tour, snapshot);
            MediaAsset cover = mediaService.requireAssignableAsset(
                    snapshot.coverMediaId(),
                    tour.getGuide().getId(),
                    MediaPurpose.TOUR_COVER
            );
            tour.applyApprovedChange(snapshot, cover);
            changeRequest.approve(reviewer, now);
            return decision(
                    reviewId,
                    AdminTourReviewType.TOUR_CHANGE,
                    changeRequest.getStatus().name(),
                    now,
                    tour
            );
        }

        Tour tour = tourRepository.findByIdForUpdate(reviewId)
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_REVIEW_NOT_FOUND));
        if (tour.getApprovalStatus() != TourApprovalStatus.PENDING_REVIEW) {
            throw new BusinessException(ErrorCode.TOUR_REVIEW_STATE_INVALID);
        }
        tour.approve(reviewer, now);
        openEligibleSessions(tour.getId(), now);
        return decision(
                reviewId,
                AdminTourReviewType.NEW_TOUR,
                tour.getApprovalStatus().name(),
                now,
                tour
        );
    }

    @Transactional
    public AdminTourReviewDecisionResponse reject(User currentAdmin, UUID reviewId, String reason) {
        Instant now = clock.instant();
        User reviewer = userRepository.getReferenceById(currentAdmin.getId());
        TourChangeRequest changeRequest = changeRequestRepository.findByIdForUpdate(reviewId).orElse(null);
        if (changeRequest != null) {
            requirePending(changeRequest);
            Tour tour = tourRepository.findByIdForUpdate(changeRequest.getTour().getId())
                    .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
            changeRequest.reject(reviewer, reason, now);
            return decision(
                    reviewId,
                    AdminTourReviewType.TOUR_CHANGE,
                    changeRequest.getStatus().name(),
                    now,
                    tour
            );
        }

        Tour tour = tourRepository.findByIdForUpdate(reviewId)
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_REVIEW_NOT_FOUND));
        if (tour.getApprovalStatus() != TourApprovalStatus.PENDING_REVIEW) {
            throw new BusinessException(ErrorCode.TOUR_REVIEW_STATE_INVALID);
        }
        tour.reject(reviewer, reason, now);
        closeManageableSessions(tour.getId());
        return decision(
                reviewId,
                AdminTourReviewType.NEW_TOUR,
                tour.getApprovalStatus().name(),
                now,
                tour
        );
    }

    private AdminTourReviewSummaryResponse toNewTourSummary(Tour tour) {
        return new AdminTourReviewSummaryResponse(
                tour.getId(),
                AdminTourReviewType.NEW_TOUR,
                tour.getId(),
                tour.getGuide().getId(),
                displayName(tour.getGuide()),
                tour.getTitle(),
                tour.getSubmittedAt()
        );
    }

    private AdminTourReviewSummaryResponse toChangeSummary(TourChangeRequest request) {
        TourChangeSnapshot snapshot = snapshotCodec.decode(request.getProposedSnapshot());
        Tour tour = request.getTour();
        return new AdminTourReviewSummaryResponse(
                request.getId(),
                AdminTourReviewType.TOUR_CHANGE,
                tour.getId(),
                tour.getGuide().getId(),
                displayName(tour.getGuide()),
                snapshot.title(),
                request.getSubmittedAt()
        );
    }

    private AdminTourReviewDetailResponse newTourDetail(Tour tour) {
        return new AdminTourReviewDetailResponse(
                tour.getId(),
                AdminTourReviewType.NEW_TOUR,
                tour.getId(),
                tour.getGuide().getId(),
                displayName(tour.getGuide()),
                tour.getSubmittedAt(),
                tour.getApprovalStatus().name(),
                tourDetail(tour),
                null
        );
    }

    private AdminTourReviewDetailResponse changeDetail(TourChangeRequest request) {
        Tour tour = request.getTour();
        TourChangeSnapshot snapshot = snapshotCodec.decode(request.getProposedSnapshot());
        TourProposalResponse proposal = tourMapper.toProposal(snapshot, request.getProposedCoverMedia());
        return new AdminTourReviewDetailResponse(
                request.getId(),
                AdminTourReviewType.TOUR_CHANGE,
                tour.getId(),
                tour.getGuide().getId(),
                displayName(tour.getGuide()),
                request.getSubmittedAt(),
                request.getStatus().name(),
                tourDetail(tour),
                proposal
        );
    }

    private AdminTourReviewDecisionResponse decision(
            UUID reviewId,
            AdminTourReviewType type,
            String status,
            Instant reviewedAt,
            Tour tour
    ) {
        return new AdminTourReviewDecisionResponse(
                reviewId,
                type,
                status,
                reviewedAt,
                tourDetail(tour)
        );
    }

    private TourDetailResponse tourDetail(Tour tour) {
        GuideProfile profile = guideProfileRepository.findByUserId(tour.getGuide().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
        List<TourSession> sessions = tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(tour.getId());
        Map<UUID, Integer> occupiedCounts = capacityService.occupiedCounts(
                sessions.stream().map(TourSession::getId).toList()
        );
        ReviewAggregate reviews = reviewQueryService.tourAggregates(List.of(tour.getId()))
                .getOrDefault(tour.getId(), ReviewAggregate.EMPTY);
        return tourMapper.toDetail(tour, sessions, profile, occupiedCounts, reviews);
    }

    private void openEligibleSessions(UUID tourId, Instant now) {
        tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(tourId).forEach(session -> {
            if (!session.getStatus().isManageable()) {
                return;
            }
            if (!session.endsAt().isAfter(now)) {
                session.complete();
            } else if (session.getStartsAt().isAfter(now)) {
                session.open();
            }
        });
    }

    private void closeManageableSessions(UUID tourId) {
        tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(tourId).stream()
                .filter(session -> session.getStatus().isManageable())
                .forEach(TourSession::close);
    }

    private void requirePending(TourChangeRequest request) {
        if (request.getStatus() != TourChangeRequestStatus.PENDING) {
            throw new BusinessException(ErrorCode.TOUR_REVIEW_STATE_INVALID);
        }
    }

    private void requireLocationUnchanged(Tour tour, TourChangeSnapshot snapshot) {
        if (!tour.getCountryCode().equals(snapshot.countryCode())
                || !tour.getCityPlaceId().equals(snapshot.cityPlaceId())
                || !tour.getCityName().equals(snapshot.cityName())
                || !tour.getTimeZoneId().equals(snapshot.timeZoneId())) {
            throw new BusinessException(ErrorCode.TOUR_LOCATION_LOCKED);
        }
    }

    private String displayName(User user) {
        return (user.getFirstName() + " " + user.getLastName()).trim();
    }
}
