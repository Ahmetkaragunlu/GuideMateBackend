package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
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
import java.util.Map;
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
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final CancellationPolicy cancellationPolicy;
    private final NotificationPublisher notificationPublisher;
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
        requireBookable(session, clock.instant());
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
        requireBookable(session, now);
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

    @Transactional
    public ReservationFinalizationResult finalizeAfterPaymentVerification(UUID reservationId) {
        TourSession session = lockSessionForReservation(reservationId);
        Reservation reservation = reservationRepository.findByIdForUpdate(reservationId)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        if (reservation.getStatus() == ReservationStatus.CONFIRMED) {
            return new ReservationFinalizationResult(reservation, false);
        }

        Instant now = clock.instant();
        if (reservation.getStatus() == ReservationStatus.PENDING_PAYMENT
                && !reservation.isHoldExpired(now)) {
            reservation.confirm();
            publishConfirmation(reservation);
            return new ReservationFinalizationResult(reservation, false);
        }
        if (reservation.getStatus() == ReservationStatus.PENDING_PAYMENT) {
            reservation.expire();
            reservationRepository.flush();
        } else if (reservation.getStatus() != ReservationStatus.EXPIRED) {
            return new ReservationFinalizationResult(reservation, true);
        }

        if (!isBookable(session, now) || hasAnotherActiveReservation(reservation, now)) {
            return new ReservationFinalizationResult(reservation, true);
        }
        int availableCapacity = capacityService.availableCapacity(
                session,
                capacityService.occupiedCount(session.getId())
        );
        if (reservation.getParticipantCount() > availableCapacity) {
            return new ReservationFinalizationResult(reservation, true);
        }
        reservation.confirmAfterVerifiedPayment();
        reservationRepository.flush();
        publishConfirmation(reservation);
        return new ReservationFinalizationResult(reservation, false);
    }

    @Transactional
    public TourSession lockSessionForReservation(UUID reservationId) {
        Reservation snapshot = reservationRepository.findById(reservationId)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        return tourSessionRepository.findByIdForUpdate(snapshot.getSession().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
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

    private void requireBookable(TourSession session, Instant now) {
        if (!isBookable(session, now)) {
            throw new BusinessException(ErrorCode.SESSION_NOT_BOOKABLE);
        }
    }

    private boolean isBookable(TourSession session, Instant now) {
        User guide = session.getTour().getGuide();
        return session.getTour().getApprovalStatus() == TourApprovalStatus.APPROVED
                && session.getStatus() == TourSessionStatus.OPEN_FOR_BOOKING
                && session.getStartsAt().isAfter(now)
                && guide.getAccountStatus() == AccountStatus.ACTIVE
                && guide.hasRole(RoleType.ROLE_GUIDE);
    }

    private boolean hasAnotherActiveReservation(Reservation reservation, Instant now) {
        Reservation active = reservationRepository.findActiveBySessionAndTouristForUpdate(
                        reservation.getSession().getId(),
                        reservation.getTourist().getId(),
                        ACTIVE_STATUSES
                )
                .orElse(null);
        if (active == null || active.getId().equals(reservation.getId())) {
            return false;
        }
        if (active.isHoldExpired(now)) {
            active.expire();
            reservationRepository.flush();
            return false;
        }
        return true;
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

    private void publishConfirmation(Reservation reservation) {
        Map<String, Object> payload = Map.of(
                "reservationId", reservation.getId().toString(),
                "sessionId", reservation.getSession().getId().toString(),
                "tourId", reservation.getSession().getTour().getId().toString(),
                "tourTitle", reservation.getSession().getTour().getTitle(),
                "participantCount", reservation.getParticipantCount(),
                "amountMinor", reservation.getTotalPriceMinor(),
                "currencyCode", reservation.getCurrencyCode()
        );
        notificationPublisher.publish(new NotificationCommand(
                reservation.getTourist().getId(),
                NotificationType.RESERVATION_CONFIRMED,
                null,
                payload
        ));
        notificationPublisher.publish(new NotificationCommand(
                reservation.getSession().getTour().getGuide().getId(),
                NotificationType.TOUR_PURCHASED,
                reservation.getTourist().getId(),
                payload
        ));
    }

}
