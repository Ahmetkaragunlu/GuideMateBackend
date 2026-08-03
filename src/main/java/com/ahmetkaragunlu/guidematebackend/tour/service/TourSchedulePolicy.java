package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TourSchedulePolicy {

    private static final List<TourSessionStatus> MANAGEABLE_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );
    private static final List<TourApprovalStatus> NON_BLOCKING_TOUR_STATUSES = List.of(
            TourApprovalStatus.REJECTED,
            TourApprovalStatus.ARCHIVED
    );

    private final TourSessionRepository tourSessionRepository;

    public void validateNewSchedule(
            Long guideId,
            Instant startsAt,
            int durationMinutes,
            Instant now
    ) {
        validateFuture(startsAt, now);
        Instant endsAt = startsAt.plus(durationMinutes, ChronoUnit.MINUTES);
        List<TourSession> candidates = tourSessionRepository.findScheduleCandidates(
                guideId,
                endsAt,
                MANAGEABLE_STATUSES,
                NON_BLOCKING_TOUR_STATUSES
        );
        rejectOverlap(candidates, startsAt);
    }

    public void validateUpdatedSchedule(
            Long guideId,
            UUID sessionId,
            Instant startsAt,
            int durationMinutes,
            Instant now
    ) {
        validateFuture(startsAt, now);
        Instant endsAt = startsAt.plus(durationMinutes, ChronoUnit.MINUTES);
        List<TourSession> candidates = tourSessionRepository.findScheduleCandidates(
                guideId,
                sessionId,
                endsAt,
                MANAGEABLE_STATUSES,
                NON_BLOCKING_TOUR_STATUSES
        );
        rejectOverlap(candidates, startsAt);
    }

    public void validateFuture(Instant startsAt, Instant now) {
        if (!startsAt.isAfter(now)) {
            throw new BusinessException(ErrorCode.SESSION_ALREADY_STARTED);
        }
    }

    private void rejectOverlap(List<TourSession> candidates, Instant startsAt) {
        if (candidates.stream().anyMatch(candidate -> candidate.endsAt().isAfter(startsAt))) {
            throw new BusinessException(ErrorCode.SCHEDULE_CONFLICT);
        }
    }
}
