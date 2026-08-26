package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TourDetailQueryService {

    private final TourSessionRepository tourSessionRepository;
    private final GuideProfileRepository guideProfileRepository;
    private final ReservationCapacityService capacityService;
    private final ReviewQueryService reviewQueryService;
    private final TourMapper tourMapper;

    public TourDetailResponse getDetail(Tour tour) {
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
}
