package com.ahmetkaragunlu.guidematebackend.reservation.service.booking;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.config.ReservationProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.lifecycle.CancellationPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.service.snapshot.PurchaseSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.reservation.service.snapshot.PurchaseSnapshotFactory;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
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
    private final ReservationBookabilityPolicy bookabilityPolicy;
    private final ReservationProperties properties;
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final CancellationPolicy cancellationPolicy;
    private final Clock clock;

    @Transactional(readOnly = true)
    public ReservationPurchasePreview previewPurchase(
            User currentUser,
            UUID sessionId,
            int participantCount
    ) {
        requireTourist(currentUser);
        requireParticipantCount(participantCount);
        TourSession session = tourSessionRepository.findById(sessionId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
        bookabilityPolicy.requireBookable(session, clock.instant());
        int occupiedCount = capacityService.occupiedCount(sessionId);
        if (participantCount > capacityService.availableCapacity(session, occupiedCount)) {
            throw new BusinessException(ErrorCode.CAPACITY_NOT_AVAILABLE);
        }
        return new ReservationPurchasePreview(
                sessionId,
                participantCount,
                calculateTotalPrice(session, participantCount),
                session.getCurrencyCode()
        );
    }

    @Transactional
    public Reservation createHold(
            User currentUser,
            UUID sessionId,
            int participantCount,
            String idempotencyKey
    ) {
        requireTourist(currentUser);
        requireParticipantCount(participantCount);
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
        Reservation previous = findPreviousReservation(currentUser.getId(), normalizedKey);
        if (previous != null) {
            return requireMatchingReservation(previous, sessionId, participantCount);
        }

        Instant now = clock.instant();
        TourSession session = tourSessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
        previous = findPreviousReservation(currentUser.getId(), normalizedKey);
        if (previous != null) {
            return requireMatchingReservation(previous, sessionId, participantCount);
        }
        bookabilityPolicy.requireBookable(session, now);
        expireStaleExistingReservation(currentUser.getId(), sessionId, now);

        int occupiedCount = capacityService.occupiedCount(sessionId);
        if (participantCount > capacityService.availableCapacity(session, occupiedCount)) {
            throw new BusinessException(ErrorCode.CAPACITY_NOT_AVAILABLE);
        }

        long totalPriceMinor = calculateTotalPrice(session, participantCount);
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

    private Reservation findPreviousReservation(Long touristId, String idempotencyKey) {
        return reservationRepository.findByTourist_IdAndIdempotencyKey(touristId, idempotencyKey)
                .orElse(null);
    }

    private Reservation requireMatchingReservation(
            Reservation reservation,
            UUID sessionId,
            int participantCount
    ) {
        if (reservation.getSession().getId().equals(sessionId)
                && reservation.getParticipantCount() == participantCount) {
            return reservation;
        }
        throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
    }

    private void requireTourist(User currentUser) {
        if (!currentUser.hasRole(RoleType.ROLE_TOURIST)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
    }

    private void requireParticipantCount(int participantCount) {
        if (participantCount < 1) {
            throw new BusinessException(ErrorCode.INVALID_PARTICIPANT_COUNT);
        }
    }

    private long calculateTotalPrice(TourSession session, int participantCount) {
        try {
            return Math.multiplyExact(session.getPriceMinor(), participantCount);
        } catch (ArithmeticException exception) {
            throw new BusinessException(ErrorCode.DATA_CONFLICT, exception);
        }
    }

}
