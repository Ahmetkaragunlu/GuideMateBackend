package com.ahmetkaragunlu.guidematebackend.reservation.service.lifecycle;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.common.validation.VersionPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.checkout.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.payment.service.refund.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.request.CancelReservationRequest;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.response.ReservationCancellationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.mapper.ReservationResponseAssembler;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReservationCancellationService {

    private final ReservationRepository reservationRepository;
    private final ReservationResponseAssembler responseAssembler;
    private final CancellationPolicy cancellationPolicy;
    private final Clock clock;
    private final IdempotencyKeyPolicy idempotencyKeyPolicy;
    private final VersionPolicy versionPolicy;
    private final PaymentRefundService paymentRefundService;
    private final GuideEarningService guideEarningService;
    private final ReservationFinalizationService finalizationService;
    private final PaymentIntentService paymentIntentService;
    private final NotificationPublisher notificationPublisher;

    @Transactional
    public ReservationCancellationResponse cancel(
            User currentUser,
            UUID reservationId,
            String idempotencyKey,
            CancelReservationRequest request
    ) {
        String normalizedKey = idempotencyKeyPolicy.normalize(idempotencyKey);
        Reservation previousCancellation = reservationRepository
                .findByTourist_IdAndCancellationIdempotencyKey(currentUser.getId(), normalizedKey)
                .orElse(null);
        if (previousCancellation != null) {
            if (previousCancellation.getId().equals(reservationId)) {
                return cancellationResponse(previousCancellation);
            }
            throw new BusinessException(ErrorCode.IDEMPOTENCY_CONFLICT);
        }
        Reservation snapshot = reservationRepository.findOwnedDetails(reservationId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        finalizationService.lockSessionForReservation(snapshot.getId());
        Reservation reservation = reservationRepository.findOwnedByIdForUpdate(reservationId, currentUser.getId())
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
                responseAssembler.toResponse(reservation),
                reservation.getCancellationRefundEligibility(),
                refund == null ? null : refund.getId(),
                refund == null ? null : refund.getStatus()
        );
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
                payload,
                "reservation:" + reservation.getId()
        ));
        notificationPublisher.publish(new NotificationCommand(
                reservation.getSession().getTour().getGuide().getId(),
                NotificationType.RESERVATION_CANCELLED,
                reservation.getTourist().getId(),
                payload,
                "reservation:" + reservation.getId()
        ));
    }
}
