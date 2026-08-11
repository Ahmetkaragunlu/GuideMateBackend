package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
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
    private final PaymentRefundService paymentRefundService;
    private final GuideEarningService guideEarningService;
    private final PaymentIntentService paymentIntentService;
    private final NotificationPublisher notificationPublisher;

    @Transactional
    public void cancelForSession(
            UUID sessionId,
            ReservationCancellationActor actor,
            String reason,
            Instant cancelledAt,
            User requestedBy
    ) {
        reservationRepository.findBySessionIdAndStatusInForUpdate(
                        sessionId,
                        CANCELLABLE_STATUSES
                )
                .forEach(reservation -> {
                    RefundEligibility eligibility = cancellationPolicy.operatorEligibility(reservation);
                    reservation.cancel(actor, reason, cancelledAt, null, eligibility);
                    paymentIntentService.cancelPendingForReservation(reservation.getId());
                    if (eligibility == RefundEligibility.FULL_REFUND) {
                        paymentRefundService.requestFullRefundForReservation(
                                reservation.getId(),
                                requestedBy,
                                "session-cancel:" + reservation.getId()
                        );
                        guideEarningService.reverse(reservation.getId());
                    }
                    notificationPublisher.publish(new NotificationCommand(
                            reservation.getTourist().getId(),
                            NotificationType.TOUR_CANCELLED,
                            requestedBy.getId(),
                            Map.of(
                                    "reservationId", reservation.getId().toString(),
                                    "sessionId", reservation.getSession().getId().toString(),
                                    "tourId", reservation.getSession().getTour().getId().toString(),
                                    "tourTitle", reservation.getSession().getTour().getTitle(),
                                    "refundEligibility", eligibility.name()
                            )
                    ));
                });
    }

    @Transactional
    public void completeForSession(UUID sessionId) {
        reservationRepository.findBySessionIdAndStatusInForUpdate(
                        sessionId,
                        List.of(ReservationStatus.CONFIRMED)
                )
                .forEach(reservation -> {
                    reservation.complete();
                    guideEarningService.makeAvailable(reservation.getId());
                    notificationPublisher.publish(new NotificationCommand(
                            reservation.getTourist().getId(),
                            NotificationType.REVIEW_REQUEST,
                            null,
                            Map.of(
                                    "reservationId", reservation.getId().toString(),
                                    "sessionId", reservation.getSession().getId().toString(),
                                    "tourId", reservation.getSession().getTour().getId().toString(),
                                    "tourTitle", reservation.getSession().getTour().getTitle()
                            )
                    ));
                });
    }
}
