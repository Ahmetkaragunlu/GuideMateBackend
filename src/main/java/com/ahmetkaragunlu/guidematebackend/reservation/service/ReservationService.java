package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationTripStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.CancelReservationRequest;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationCancellationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.mapper.ReservationMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReservationService {

    private static final List<ReservationStatus> PAST_STATUSES = List.of(
            ReservationStatus.COMPLETED,
            ReservationStatus.CANCELLED
    );

    private final ReservationRepository reservationRepository;
    private final ReviewQueryService reviewQueryService;
    private final ReservationMapper reservationMapper;
    private final CancellationPolicy cancellationPolicy;
    private final Clock clock;

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
        Map<UUID, ReviewResponse> reviews = reviewsByReservationId(reservations.getContent());
        return PageResponse.from(reservations.map(reservation -> reservationMapper.toResponse(
                reservation,
                reviews.get(reservation.getId())
        )));
    }

    @Transactional(readOnly = true)
    public ReservationResponse getOwnedReservation(User currentUser, UUID reservationId) {
        Reservation reservation = reservationRepository.findOwnedDetails(
                        reservationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        return reservationMapper.toResponse(
                reservation,
                reviewQueryService.reviewByReservationId(reservationId)
        );
    }

    @Transactional
    public ReservationCancellationResponse cancel(
            User currentUser,
            UUID reservationId,
            String idempotencyKey,
            CancelReservationRequest request
    ) {
        String normalizedKey = normalizeIdempotencyKey(idempotencyKey);
        Reservation previousCancellation = reservationRepository
                .findByTourist_IdAndCancellationIdempotencyKey(
                        currentUser.getId(),
                        normalizedKey
                )
                .orElse(null);
        if (previousCancellation != null) {
            if (previousCancellation.getId().equals(reservationId)) {
                return cancellationResponse(previousCancellation);
            }
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }
        Reservation reservation = reservationRepository.findOwnedByIdForUpdate(
                        reservationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        requireVersion(reservation.getVersion(), request.version());
        if (reservation.getStatus() != ReservationStatus.PENDING_PAYMENT
                && reservation.getStatus() != ReservationStatus.CONFIRMED) {
            throw new BusinessException(ErrorCode.RESERVATION_NOT_CANCELLABLE);
        }
        Instant now = clock.instant();
        if (!reservation.getSession().getStartsAt().isAfter(now)) {
            throw new BusinessException(ErrorCode.RESERVATION_NOT_CANCELLABLE);
        }
        RefundEligibility refundEligibility = cancellationPolicy.touristEligibility(reservation, now);
        reservation.cancel(
                ReservationCancellationActor.TOURIST,
                trimToNull(request.reason()),
                now,
                normalizedKey,
                refundEligibility
        );
        try {
            reservationRepository.flush();
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT, exception);
        }
        return cancellationResponse(reservation);
    }

    private ReservationCancellationResponse cancellationResponse(Reservation reservation) {
        return new ReservationCancellationResponse(
                reservationMapper.toResponse(
                        reservation,
                        reviewQueryService.reviewByReservationId(reservation.getId())
                ),
                reservation.getCancellationRefundEligibility()
        );
    }

    private Map<UUID, ReviewResponse> reviewsByReservationId(List<Reservation> reservations) {
        Set<UUID> reservationIds = reservations.stream()
                .map(Reservation::getId)
                .collect(Collectors.toSet());
        return reviewQueryService.reviewsByReservationIds(reservationIds);
    }

    private void requireVersion(long actualVersion, long requestedVersion) {
        if (actualVersion != requestedVersion) {
            throw new BusinessException(ErrorCode.CONCURRENT_UPDATE);
        }
    }

    private String normalizeIdempotencyKey(String idempotencyKey) {
        if (idempotencyKey == null || idempotencyKey.isBlank() || idempotencyKey.length() > 128) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
        return idempotencyKey.trim();
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
