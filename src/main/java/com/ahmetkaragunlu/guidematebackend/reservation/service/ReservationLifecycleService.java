package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReservationLifecycleService {

    private static final List<ReservationStatus> CANCELLABLE_STATUSES = List.of(
            ReservationStatus.PENDING_PAYMENT,
            ReservationStatus.CONFIRMED
    );

    private final ReservationRepository reservationRepository;
    private final CancellationPolicy cancellationPolicy;

    @Transactional
    public void cancelForSession(
            UUID sessionId,
            ReservationCancellationActor actor,
            String reason,
            Instant cancelledAt
    ) {
        reservationRepository.findBySessionIdAndStatusInForUpdate(
                        sessionId,
                        CANCELLABLE_STATUSES
                )
                .forEach(reservation -> reservation.cancel(
                        actor,
                        reason,
                        cancelledAt,
                        null,
                        cancellationPolicy.operatorEligibility(reservation)
                ));
    }

    @Transactional
    public void completeForSession(UUID sessionId) {
        reservationRepository.findBySessionIdAndStatusInForUpdate(
                        sessionId,
                        List.of(ReservationStatus.CONFIRMED)
                )
                .forEach(Reservation::complete);
    }
}
