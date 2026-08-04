package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.profile.dto.GuidePerformanceSummary;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.GuideParticipantSummary;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.GuideCompletedSessionCount;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GuidePerformanceService {

    private final TourSessionRepository tourSessionRepository;
    private final ReservationRepository reservationRepository;
    private final ReviewQueryService reviewQueryService;
    private final GuideLevelPolicy guideLevelPolicy;

    @Transactional(readOnly = true)
    public GuidePerformanceSummary get(Long guideId) {
        return getAll(Set.of(guideId)).get(guideId);
    }

    @Transactional(readOnly = true)
    public Map<Long, GuidePerformanceSummary> getAll(Collection<Long> guideIds) {
        if (guideIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, Long> completedSessions = tourSessionRepository.countCompletedSessionsByGuideIds(
                        guideIds,
                        TourSessionStatus.COMPLETED
                ).stream()
                .collect(Collectors.toMap(
                        GuideCompletedSessionCount::getGuideId,
                        GuideCompletedSessionCount::getCompletedSessionCount
                ));
        Map<Long, Long> participants = reservationRepository.sumCompletedParticipantsByGuideIds(
                        guideIds,
                        ReservationStatus.COMPLETED
                ).stream()
                .collect(Collectors.toMap(
                        GuideParticipantSummary::getGuideId,
                        GuideParticipantSummary::getParticipantCount
                ));
        Map<Long, ReviewAggregate> ratings = reviewQueryService.guideAggregates(guideIds);

        return guideIds.stream().collect(Collectors.toMap(
                Function.identity(),
                guideId -> summary(
                        completedSessions.getOrDefault(guideId, 0L),
                        participants.getOrDefault(guideId, 0L),
                        ratings.getOrDefault(guideId, ReviewAggregate.EMPTY)
                )
        ));
    }

    private GuidePerformanceSummary summary(
            long completedSessionCount,
            long totalParticipantCount,
            ReviewAggregate reviews
    ) {
        return new GuidePerformanceSummary(
                completedSessionCount,
                totalParticipantCount,
                reviews.averageRating(),
                reviews.reviewCount(),
                guideLevelPolicy.resolve(
                        completedSessionCount,
                        reviews.averageRating(),
                        reviews.reviewCount()
                )
        );
    }
}
