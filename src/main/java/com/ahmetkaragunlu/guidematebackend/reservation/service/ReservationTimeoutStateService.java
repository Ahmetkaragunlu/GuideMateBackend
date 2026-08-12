package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReservationTimeoutStateService {

    private static final List<PaymentStatus> TIMEOUT_CANDIDATE_STATUSES = List.of(
            PaymentStatus.PENDING,
            PaymentStatus.REQUIRES_ACTION,
            PaymentStatus.VERIFYING
    );

    private final ReservationBookingService reservationBookingService;
    private final ReservationRepository reservationRepository;
    private final PaymentRepository paymentRepository;
    private final Clock clock;

    @Transactional
    public void expireHold(UUID reservationId) {
        reservationBookingService.lockSessionForReservation(reservationId);
        Reservation reservation = reservationRepository.findByIdForUpdate(reservationId).orElse(null);
        if (reservation == null
                || reservation.getStatus() != ReservationStatus.PENDING_PAYMENT
                || !reservation.isHoldExpired(clock.instant())) {
            return;
        }

        paymentRepository.findByReservationIdAndStatusesForUpdate(
                reservationId,
                TIMEOUT_CANDIDATE_STATUSES
        ).forEach(payment -> payment.timeout());
        reservation.expire();
    }
}
