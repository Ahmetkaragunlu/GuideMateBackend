package com.ahmetkaragunlu.guidematebackend.reservation.service.finalization;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationBookabilityPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReservationFinalizationService {

    private static final List<ReservationStatus> ACTIVE_STATUSES = List.of(
            ReservationStatus.PENDING_PAYMENT,
            ReservationStatus.CONFIRMED
    );

    private final ReservationRepository reservationRepository;
    private final TourSessionRepository tourSessionRepository;
    private final ReservationCapacityService capacityService;
    private final ReservationBookabilityPolicy bookabilityPolicy;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

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

        if (!bookabilityPolicy.isBookable(session, now) || hasAnotherActiveReservation(reservation, now)) {
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
                payload,
                "reservation:" + reservation.getId()
        ));
        notificationPublisher.publish(new NotificationCommand(
                reservation.getSession().getTour().getGuide().getId(),
                NotificationType.TOUR_PURCHASED,
                reservation.getTourist().getId(),
                payload,
                "reservation:" + reservation.getId()
        ));
    }
}
