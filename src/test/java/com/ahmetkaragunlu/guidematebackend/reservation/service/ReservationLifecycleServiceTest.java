package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.payment.service.refund.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationLifecycleServiceTest {

    @Mock private ReservationRepository repository;
    @Mock private CancellationPolicy cancellationPolicy;
    @Mock private PaymentRefundService refundService;
    @Mock private GuideEarningService earningService;
    @Mock private PaymentIntentService paymentIntentService;
    @Mock private NotificationPublisher notificationPublisher;
    private ReservationLifecycleService service;

    @BeforeEach
    void setUp() {
        service = new ReservationLifecycleService(
                repository,
                cancellationPolicy,
                refundService,
                earningService,
                paymentIntentService,
                notificationPublisher
        );
    }

    @Test
    void sessionCancellationCancelsPaymentRefundsAndReversesEarning() {
        UUID sessionId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        Instant cancelledAt = Instant.parse("2026-09-24T12:00:00Z");
        User operator = org.mockito.Mockito.mock(User.class);
        User tourist = org.mockito.Mockito.mock(User.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        when(repository.findBySessionIdAndStatusInForUpdate(
                org.mockito.ArgumentMatchers.eq(sessionId),
                anyList()
        )).thenReturn(List.of(reservation));
        when(cancellationPolicy.operatorEligibility(reservation)).thenReturn(RefundEligibility.FULL_REFUND);
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getTourist()).thenReturn(tourist);
        when(tourist.getId()).thenReturn(50L);
        when(operator.getId()).thenReturn(99L);
        when(reservation.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(UUID.randomUUID());
        when(tour.getTitle()).thenReturn("İstanbul Tarih Turu");

        service.cancelForSession(
                sessionId,
                ReservationCancellationActor.ADMIN,
                "Olumsuz hava",
                cancelledAt,
                operator
        );

        verify(reservation).cancel(
                ReservationCancellationActor.ADMIN,
                "Olumsuz hava",
                cancelledAt,
                null,
                RefundEligibility.FULL_REFUND
        );
        verify(paymentIntentService).cancelPendingForReservation(reservationId);
        verify(refundService).requestFullRefundForReservation(
                reservationId,
                operator,
                "session-cancel:" + reservationId
        );
        verify(earningService).reverse(reservationId);
        verify(notificationPublisher).publish(org.mockito.ArgumentMatchers.any());
    }
}
