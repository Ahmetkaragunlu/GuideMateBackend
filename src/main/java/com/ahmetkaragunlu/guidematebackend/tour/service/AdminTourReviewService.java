package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewDecisionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewType;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AdminTourReviewService {

    private final TourRepository tourRepository;
    private final TourSessionRepository tourSessionRepository;
    private final TourChangeRequestRepository changeRequestRepository;
    private final UserRepository userRepository;
    private final MediaService mediaService;
    private final TourContentFactory tourContentFactory;
    private final TourChangeSnapshotCodec snapshotCodec;
    private final TourLocationPolicy locationPolicy;
    private final TourDetailQueryService tourDetailQueryService;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

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
            locationPolicy.requireUnchanged(tour, snapshot);
            MediaAsset cover = mediaService.requireAssignableAsset(
                    snapshot.coverMediaId(),
                    tour.getGuide().getId(),
                    MediaPurpose.TOUR_COVER
            );
            tour.applyApprovedChange(snapshot, cover);
            changeRequest.approve(reviewer, now);
            publishDecision(
                    tour,
                    currentAdmin,
                    NotificationType.TOUR_CHANGE_APPROVED,
                    reviewId,
                    null
            );
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
        publishDecision(tour, currentAdmin, NotificationType.TOUR_APPROVED, reviewId, null);
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
            publishDecision(
                    tour,
                    currentAdmin,
                    NotificationType.TOUR_CHANGE_REJECTED,
                    reviewId,
                    reason
            );
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
        publishDecision(tour, currentAdmin, NotificationType.TOUR_REJECTED, reviewId, reason);
        return decision(
                reviewId,
                AdminTourReviewType.NEW_TOUR,
                tour.getApprovalStatus().name(),
                now,
                tour
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
                tourDetailQueryService.getDetail(tour)
        );
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

    private void publishDecision(
            Tour tour,
            User admin,
            NotificationType type,
            UUID reviewId,
            String rejectionReason
    ) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("tourId", tour.getId().toString());
        payload.put("reviewId", reviewId.toString());
        payload.put("tourTitle", tour.getTitle());
        if (rejectionReason != null) {
            payload.put("rejectionReason", rejectionReason);
        }
        notificationPublisher.publish(new NotificationCommand(
                tour.getGuide().getId(),
                type,
                admin.getId(),
                payload
        ));
    }
}
