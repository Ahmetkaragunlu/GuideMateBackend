package com.ahmetkaragunlu.guidematebackend.reservation.service.query;

import com.ahmetkaragunlu.guidematebackend.common.dto.response.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationTripStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.response.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.mapper.ReservationResponseAssembler;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReservationQueryService {

    private static final List<ReservationStatus> PAST_STATUSES = List.of(
            ReservationStatus.COMPLETED,
            ReservationStatus.CANCELLED
    );

    private final ReservationRepository reservationRepository;
    private final ReservationResponseAssembler responseAssembler;

    @Transactional(readOnly = true)
    public PageResponse<ReservationResponse> getMyTrips(
            User currentUser,
            ReservationTripStatus status,
            int page,
            int size
    ) {
        PageRequest pageRequest = PageRequest.of(page, size);
        Page<Reservation> reservations = switch (status) {
            case UPCOMING -> reservationRepository.findUpcomingTrips(
                    currentUser.getId(),
                    ReservationStatus.CONFIRMED,
                    pageRequest
            );
            case PAST -> reservationRepository.findPastTrips(
                    currentUser.getId(),
                    PAST_STATUSES,
                    pageRequest
            );
        };
        return PageResponse.from(responseAssembler.toPage(reservations));
    }

    @Transactional(readOnly = true)
    public ReservationResponse getOwnedReservation(User currentUser, UUID reservationId) {
        Reservation reservation = reservationRepository.findOwnedDetails(
                        reservationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        return responseAssembler.toResponse(reservation);
    }
}
