package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationLifecycleService;
import com.ahmetkaragunlu.guidematebackend.tour.config.TourProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourCancellationActor;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.CancelTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.CreateTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.UpdateTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSessionResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TourSessionService {

    private final TourRepository tourRepository;
    private final TourSessionRepository tourSessionRepository;
    private final TourSchedulePolicy schedulePolicy;
    private final TourMapper tourMapper;
    private final TourProperties tourProperties;
    private final ReservationCapacityService capacityService;
    private final ReservationLifecycleService reservationLifecycleService;
    private final Clock clock;

    @Transactional
    public TourSessionResponse addSession(
            User currentUser,
            UUID tourId,
            CreateTourSessionRequest request
    ) {
        Tour tour = tourRepository.findOwnedByIdForUpdate(tourId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        if (tour.getApprovalStatus() != TourApprovalStatus.APPROVED) {
            throw new BusinessException(ErrorCode.TOUR_NOT_APPROVED);
        }
        schedulePolicy.validateNewSchedule(
                currentUser.getId(),
                request.startsAt(),
                request.durationMinutes(),
                clock.instant()
        );
        TourSession session = TourSession.create(
                tour,
                request.meetingPoint(),
                request.startsAt(),
                request.durationMinutes(),
                request.priceMinor(),
                tourProperties.currencyCode(),
                request.capacity(),
                TourSessionStatus.OPEN_FOR_BOOKING
        );
        return tourMapper.toSession(tourSessionRepository.save(session), 0);
    }

    @Transactional
    public TourSessionResponse updateSession(
            User currentUser,
            UUID sessionId,
            UpdateTourSessionRequest request
    ) {
        TourSession session = requireOwnedSession(currentUser.getId(), sessionId);
        requireVersion(session.getVersion(), request.version());
        requireManageableFuture(session);
        int occupiedCount = capacityService.occupiedCount(sessionId);
        if (request.capacity() < occupiedCount) {
            throw new BusinessException(ErrorCode.CAPACITY_BELOW_BOOKED_COUNT);
        }
        if (session.hasScheduleChanges(
                request.meetingPoint(),
                request.startsAt(),
                request.durationMinutes()
        ) && capacityService.hasActiveReservation(sessionId)) {
            throw new BusinessException(ErrorCode.SESSION_HAS_RESERVATIONS);
        }
        schedulePolicy.validateUpdatedSchedule(
                currentUser.getId(),
                sessionId,
                request.startsAt(),
                request.durationMinutes(),
                clock.instant()
        );
        session.updateSchedule(
                request.meetingPoint(),
                request.startsAt(),
                request.durationMinutes(),
                request.priceMinor(),
                request.capacity()
        );
        tourSessionRepository.flush();
        return tourMapper.toSession(session, occupiedCount);
    }

    @Transactional
    public TourSessionResponse openSession(User currentUser, UUID sessionId) {
        TourSession session = requireOwnedSession(currentUser.getId(), sessionId);
        requireManageableFuture(session);
        if (session.getTour().getApprovalStatus() != TourApprovalStatus.APPROVED) {
            throw new BusinessException(ErrorCode.TOUR_NOT_APPROVED);
        }
        int occupiedCount = capacityService.occupiedCount(sessionId);
        if (capacityService.availableCapacity(session, occupiedCount) < 1) {
            throw new BusinessException(ErrorCode.CAPACITY_NOT_AVAILABLE);
        }
        session.open();
        tourSessionRepository.flush();
        return tourMapper.toSession(session, occupiedCount);
    }

    @Transactional
    public TourSessionResponse closeSession(User currentUser, UUID sessionId) {
        TourSession session = requireOwnedSession(currentUser.getId(), sessionId);
        requireManageableFuture(session);
        session.close();
        tourSessionRepository.flush();
        return tourMapper.toSession(session, capacityService.occupiedCount(sessionId));
    }

    @Transactional
    public TourSessionResponse cancelSession(
            User currentUser,
            UUID sessionId,
            String idempotencyKey,
            CancelTourSessionRequest request
    ) {
        String normalizedKey = normalizeIdempotencyKey(idempotencyKey);
        TourSession session = requireOwnedSession(currentUser.getId(), sessionId);
        if (session.getStatus() == TourSessionStatus.CANCELLED
                && normalizedKey.equals(session.getCancellationIdempotencyKey())) {
            return tourMapper.toSession(session, 0);
        }
        requireManageableFuture(session);
        session.cancel(
                TourCancellationActor.GUIDE,
                request.reason(),
                clock.instant(),
                normalizedKey
        );
        reservationLifecycleService.cancelForSession(
                sessionId,
                ReservationCancellationActor.GUIDE,
                request.reason(),
                session.getCancelledAt()
        );
        tourSessionRepository.flush();
        return tourMapper.toSession(session, 0);
    }

    private String normalizeIdempotencyKey(String idempotencyKey) {
        if (idempotencyKey == null || idempotencyKey.isBlank() || idempotencyKey.length() > 128) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
        return idempotencyKey.trim();
    }

    private TourSession requireOwnedSession(Long guideId, UUID sessionId) {
        return tourSessionRepository.findOwnedByIdForUpdate(sessionId, guideId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
    }

    private void requireManageableFuture(TourSession session) {
        if (!session.getStatus().isManageable()) {
            throw new BusinessException(ErrorCode.SESSION_STATUS_NOT_MANAGEABLE);
        }
        if (!session.getStartsAt().isAfter(clock.instant())) {
            throw new BusinessException(ErrorCode.SESSION_ALREADY_STARTED);
        }
    }

    private void requireVersion(long actualVersion, long requestedVersion) {
        if (actualVersion != requestedVersion) {
            throw new BusinessException(ErrorCode.CONCURRENT_UPDATE);
        }
    }
}
