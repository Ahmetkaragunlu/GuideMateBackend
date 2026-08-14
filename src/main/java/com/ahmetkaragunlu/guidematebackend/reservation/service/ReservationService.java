package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.common.validation.VersionPolicy;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
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
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
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
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final VersionPolicy versionPolicy;
    private final PaymentRefundService paymentRefundService;
    private final GuideEarningService guideEarningService;
    private final ReservationBookingService reservationBookingService;
    private final PaymentIntentService paymentIntentService;
    private final NotificationPublisher notificationPublisher;

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
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
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
        Reservation snapshot = reservationRepository.findOwnedDetails(
                        reservationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        reservationBookingService.lockSessionForReservation(snapshot.getId());
        Reservation reservation = reservationRepository.findOwnedByIdForUpdate(
                        reservationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        versionPolicy.requireMatch(reservation.getVersion(), request.version());
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
        paymentIntentService.cancelPendingForReservation(reservation.getId());
        try {
            reservationRepository.flush();
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT, exception);
        }
        Refund refund = null;
        if (refundEligibility == RefundEligibility.FULL_REFUND) {
            refund = paymentRefundService.requestFullRefundForReservation(
                    reservation.getId(),
                    currentUser,
                    "reservation-cancel:" + reservation.getId()
            );
            guideEarningService.reverse(reservation.getId());
        }
        publishCancellation(reservation);
        return cancellationResponse(reservation, refund);
    }

    private ReservationCancellationResponse cancellationResponse(Reservation reservation) {
        return cancellationResponse(
                reservation,
                paymentRefundService.findLatestForReservation(reservation.getId())
        );
    }

    private ReservationCancellationResponse cancellationResponse(Reservation reservation, Refund refund) {
        return new ReservationCancellationResponse(
                reservationMapper.toResponse(
                        reservation,
                        reviewQueryService.reviewByReservationId(reservation.getId())
                ),
                reservation.getCancellationRefundEligibility(),
                refund == null ? null : refund.getId(),
                refund == null ? null : refund.getStatus()
        );
    }

    private Map<UUID, ReviewResponse> reviewsByReservationId(List<Reservation> reservations) {
        Set<UUID> reservationIds = reservations.stream()
                .map(Reservation::getId)
                .collect(Collectors.toSet());
        return reviewQueryService.reviewsByReservationIds(reservationIds);
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private void publishCancellation(Reservation reservation) {
        Map<String, Object> payload = Map.of(
                "reservationId", reservation.getId().toString(),
                "sessionId", reservation.getSession().getId().toString(),
                "tourId", reservation.getSession().getTour().getId().toString(),
                "tourTitle", reservation.getSession().getTour().getTitle(),
                "refundEligibility", reservation.getCancellationRefundEligibility().name()
        );
        notificationPublisher.publish(new NotificationCommand(
                reservation.getTourist().getId(),
                NotificationType.RESERVATION_CANCELLED,
                null,
                payload
        ));
        notificationPublisher.publish(new NotificationCommand(
                reservation.getSession().getTour().getGuide().getId(),
                NotificationType.RESERVATION_CANCELLED,
                reservation.getTourist().getId(),
                payload
        ));
    }
}
