package com.ahmetkaragunlu.guidematebackend.review.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.dto.TourReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.mapper.ReviewMapper;
import com.ahmetkaragunlu.guidematebackend.review.repository.GuideRatingSummary;
import com.ahmetkaragunlu.guidematebackend.review.repository.ReviewRepository;
import com.ahmetkaragunlu.guidematebackend.review.repository.TourRatingSummary;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReviewQueryService {

    private final ReviewRepository reviewRepository;
    private final TourRepository tourRepository;
    private final ReviewMapper reviewMapper;

    @Transactional(readOnly = true)
    public Map<UUID, ReviewResponse> reviewsByReservationIds(Collection<UUID> reservationIds) {
        if (reservationIds.isEmpty()) {
            return Map.of();
        }
        return reviewRepository.findAllByReservation_IdIn(reservationIds).stream()
                .collect(Collectors.toMap(
                        review -> review.getReservation().getId(),
                        reviewMapper::toResponse
                ));
    }

    @Transactional(readOnly = true)
    public ReviewResponse reviewByReservationId(UUID reservationId) {
        return reviewRepository.findByReservation_Id(reservationId)
                .map(reviewMapper::toResponse)
                .orElse(null);
    }

    @Transactional(readOnly = true)
    public PageResponse<TourReviewResponse> getTourReviews(UUID tourId, int page, int size) {
        var tour = tourRepository.findDetailsById(tourId)
                .filter(candidate -> candidate.getApprovalStatus() == TourApprovalStatus.APPROVED)
                .filter(candidate -> candidate.getGuide().getAccountStatus() == AccountStatus.ACTIVE)
                .filter(candidate -> candidate.getGuide().getRole() != null)
                .filter(candidate -> RoleType.ROLE_GUIDE.name().equals(
                        candidate.getGuide().getRole().getName()
                ))
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        Page<Review> reviews = reviewRepository.findPublicByTourId(
                tour.getId(),
                PageRequest.of(page, size)
        );
        return PageResponse.from(reviews.map(reviewMapper::toPublicResponse));
    }

    @Transactional(readOnly = true)
    public Map<UUID, ReviewAggregate> tourAggregates(Collection<UUID> tourIds) {
        if (tourIds.isEmpty()) {
            return Map.of();
        }
        return reviewRepository.summarizeByTourIds(tourIds).stream()
                .collect(Collectors.toMap(
                        TourRatingSummary::getTourId,
                        summary -> new ReviewAggregate(
                                summary.getAverageRating(),
                                summary.getReviewCount()
                        )
                ));
    }

    @Transactional(readOnly = true)
    public Map<Long, ReviewAggregate> guideAggregates(Collection<Long> guideIds) {
        if (guideIds.isEmpty()) {
            return Map.of();
        }
        return reviewRepository.summarizeByGuideIds(guideIds).stream()
                .collect(Collectors.toMap(
                        GuideRatingSummary::getGuideId,
                        summary -> new ReviewAggregate(
                                summary.getAverageRating(),
                                summary.getReviewCount()
                        )
                ));
    }
}
