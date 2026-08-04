package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.SessionOccupancy;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReservationCapacityService {

    private static final List<ReservationStatus> OCCUPIED_STATUSES = List.of(
            ReservationStatus.CONFIRMED,
            ReservationStatus.COMPLETED
    );

    private final ReservationRepository reservationRepository;
    private final Clock clock;

    @Transactional(readOnly = true)
    public int occupiedCount(UUID sessionId) {
        return toInt(reservationRepository.sumOccupancyBySessionId(
                sessionId,
                OCCUPIED_STATUSES,
                ReservationStatus.PENDING_PAYMENT,
                clock.instant()
        ));
    }

    @Transactional(readOnly = true)
    public Map<UUID, Integer> occupiedCounts(Collection<UUID> sessionIds) {
        if (sessionIds.isEmpty()) {
            return Map.of();
        }
        return reservationRepository.sumOccupancyBySessionIds(
                        sessionIds,
                        OCCUPIED_STATUSES,
                        ReservationStatus.PENDING_PAYMENT,
                        clock.instant()
                ).stream()
                .collect(Collectors.toMap(
                        SessionOccupancy::getSessionId,
                        occupancy -> toInt(occupancy.getParticipantCount())
                ));
    }

    @Transactional(readOnly = true)
    public boolean hasActiveReservation(UUID sessionId) {
        return reservationRepository.existsActiveReservation(
                sessionId,
                ReservationStatus.CONFIRMED,
                ReservationStatus.PENDING_PAYMENT,
                clock.instant()
        );
    }

    public int availableCapacity(TourSession session, int occupiedCount) {
        return Math.max(0, session.getCapacity() - occupiedCount);
    }

    private int toInt(long count) {
        return Math.toIntExact(count);
    }
}
