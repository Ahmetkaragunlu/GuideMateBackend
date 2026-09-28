package com.ahmetkaragunlu.guidematebackend.tour.service.admin;

import com.ahmetkaragunlu.guidematebackend.common.dto.response.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.change.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.change.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.review.AdminTourReviewDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.review.AdminTourReviewSummaryResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.review.AdminTourReviewType;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.review.TourProposalResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.AdminTourReviewRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.projection.AdminTourReviewSummaryProjection;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.service.content.TourChangeSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.tour.service.discovery.TourDetailQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AdminTourReviewQueryService {

    private final TourRepository tourRepository;
    private final AdminTourReviewRepository adminTourReviewRepository;
    private final TourChangeRequestRepository changeRequestRepository;

    private final TourChangeSnapshotCodec snapshotCodec;
    private final TourMapper tourMapper;
    private final TourDetailQueryService tourDetailQueryService;

    @Transactional(readOnly = true)
    public PageResponse<AdminTourReviewSummaryResponse> getPendingReviews(int page, int size) {
        return PageResponse.from(adminTourReviewRepository.findPendingReviews(
                PageRequest.of(page, size)
        ).map(this::toSummary));
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

    private AdminTourReviewSummaryResponse toSummary(AdminTourReviewSummaryProjection review) {
        return new AdminTourReviewSummaryResponse(
                review.getReviewId(),
                AdminTourReviewType.valueOf(review.getReviewType()),
                review.getTourId(),
                review.getGuideId(),
                review.getGuideDisplayName(),
                review.getTitle(),
                review.getSubmittedAt()
        );
    }

    private AdminTourReviewDetailResponse newTourDetail(Tour tour) {
        return new AdminTourReviewDetailResponse(
                tour.getId(),
                AdminTourReviewType.NEW_TOUR,
                tour.getId(),
                tour.getGuide().getId(),
                tour.getGuide().displayName(),
                tour.getSubmittedAt(),
                tour.getApprovalStatus().name(),
                tourDetailQueryService.getDetail(tour),
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
                tour.getGuide().displayName(),
                request.getSubmittedAt(),
                request.getStatus().name(),
                tourDetailQueryService.getDetail(tour),
                proposal
        );
    }
}
