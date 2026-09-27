package com.ahmetkaragunlu.guidematebackend.reservation.service.timeout;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
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

    private final ReservationFinalizationService reservationFinalizationService;
    private final ReservationRepository reservationRepository;
    private final PaymentRepository paymentRepository;
    private final Clock clock;

    @Transactional
    public void expireHold(UUID reservationId) {
        reservationFinalizationService.lockSessionForReservation(reservationId);
        Reservation reservation = reservationRepository.findByIdForUpdate(reservationId).orElse(null);
        if (reservation == null
                || reservation.getStatus() != ReservationStatus.PENDING_PAYMENT
                || !reservation.isHoldExpired(clock.instant())) {
            return;
        }

        paymentRepository.findByReservationIdAndStatusesForUpdate(
                reservationId,
                TIMEOUT_CANDIDATE_STATUSES
        ).forEach(Payment::timeout);
        reservation.expire();
    }
}
