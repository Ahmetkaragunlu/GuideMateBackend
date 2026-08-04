package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.config.ReservationProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReservationBookingService {

    private static final List<ReservationStatus> ACTIVE_STATUSES = List.of(
            ReservationStatus.PENDING_PAYMENT,
            ReservationStatus.CONFIRMED
    );

    private final ReservationRepository reservationRepository;
    private final TourSessionRepository tourSessionRepository;
    private final UserRepository userRepository;
    private final ReservationCapacityService capacityService;
    private final PurchaseSnapshotFactory snapshotFactory;
    private final PurchaseSnapshotCodec snapshotCodec;
    private final ReservationProperties properties;
    private final CancellationPolicy cancellationPolicy;
    private final Clock clock;

    @Transactional
    public Reservation createHold(
            User currentUser,
            UUID sessionId,
            int participantCount,
            String idempotencyKey
    ) {
        requireTourist(currentUser);
        requireParticipantCount(participantCount);
        String normalizedKey = normalizeIdempotencyKey(idempotencyKey);
        Reservation previous = reservationRepository.findByTourist_IdAndIdempotencyKey(
                currentUser.getId(),
                normalizedKey
        ).orElse(null);
        if (previous != null) {
            if (previous.getSession().getId().equals(sessionId)
                    && previous.getParticipantCount() == participantCount) {
                return previous;
            }
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }

        Instant now = clock.instant();
        TourSession session = tourSessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
        requireBookable(session, now);
        expireStaleExistingReservation(currentUser.getId(), sessionId, now);

        int occupiedCount = capacityService.occupiedCount(sessionId);
        if (participantCount > capacityService.availableCapacity(session, occupiedCount)) {
            throw new BusinessException(ErrorCode.CAPACITY_NOT_AVAILABLE);
        }

        long totalPriceMinor;
        try {
            totalPriceMinor = Math.multiplyExact(session.getPriceMinor(), participantCount);
        } catch (ArithmeticException exception) {
            throw new BusinessException(ErrorCode.DATA_CONFLICT, exception);
        }
        PurchaseSnapshot snapshot = snapshotFactory.create(session, participantCount, totalPriceMinor);
        Reservation reservation = Reservation.hold(
                session,
                userRepository.getReferenceById(currentUser.getId()),
                participantCount,
                session.getPriceMinor(),
                totalPriceMinor,
                session.getCurrencyCode(),
                now.plus(properties.holdDuration()),
                cancellationPolicy.currentCode(),
                cancellationPolicy.currentVersion(),
                PurchaseSnapshotFactory.CURRENT_SNAPSHOT_VERSION,
                snapshotCodec.encode(snapshot),
                normalizedKey
        );
        try {
            return reservationRepository.saveAndFlush(reservation);
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.RESERVATION_ALREADY_EXISTS, exception);
        }
    }

    @Transactional
    public Reservation finalizeAfterPaymentVerification(UUID reservationId) {
        Reservation reservation = reservationRepository.findByIdForUpdate(reservationId)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        if (reservation.isHoldExpired(clock.instant())) {
            reservation.expire();
            return reservation;
        }
        reservation.confirm();
        return reservation;
    }

    @Transactional
    public void expire(UUID reservationId) {
        Reservation reservation = reservationRepository.findByIdForUpdate(reservationId)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        if (reservation.getStatus() == ReservationStatus.PENDING_PAYMENT) {
            reservation.expire();
        }
    }

    private void expireStaleExistingReservation(Long touristId, UUID sessionId, Instant now) {
        Reservation activeReservation = reservationRepository.findActiveBySessionAndTouristForUpdate(
                sessionId,
                touristId,
                ACTIVE_STATUSES
        ).orElse(null);
        if (activeReservation == null) {
            return;
        }
        if (activeReservation.isHoldExpired(now)) {
            activeReservation.expire();
            reservationRepository.flush();
            return;
        }
        throw new BusinessException(ErrorCode.RESERVATION_ALREADY_EXISTS);
    }

    private void requireBookable(TourSession session, Instant now) {
        User guide = session.getTour().getGuide();
        boolean bookable = session.getTour().getApprovalStatus() == TourApprovalStatus.APPROVED
                && session.getStatus() == TourSessionStatus.OPEN_FOR_BOOKING
                && session.getStartsAt().isAfter(now)
                && guide.getAccountStatus() == AccountStatus.ACTIVE
                && guide.getRole() != null
                && RoleType.ROLE_GUIDE.name().equals(guide.getRole().getName());
        if (!bookable) {
            throw new BusinessException(ErrorCode.SESSION_NOT_BOOKABLE);
        }
    }

    private void requireTourist(User currentUser) {
        if (currentUser.getRole() == null
                || !RoleType.ROLE_TOURIST.name().equals(currentUser.getRole().getName())) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
    }

    private void requireParticipantCount(int participantCount) {
        if (participantCount < 1) {
            throw new BusinessException(ErrorCode.INVALID_PARTICIPANT_COUNT);
        }
    }

    private String normalizeIdempotencyKey(String idempotencyKey) {
        if (idempotencyKey == null || idempotencyKey.isBlank() || idempotencyKey.length() > 128) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
        return idempotencyKey.trim();
    }
}
