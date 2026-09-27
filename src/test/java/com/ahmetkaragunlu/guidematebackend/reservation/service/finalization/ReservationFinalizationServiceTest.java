package com.ahmetkaragunlu.guidematebackend.reservation.service.finalization;

import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationBookabilityPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationFinalizationServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @Mock private ReservationRepository reservationRepository;
    @Mock private TourSessionRepository sessionRepository;
    @Mock private ReservationCapacityService capacityService;
    @Mock private ReservationBookabilityPolicy bookabilityPolicy;
    @Mock private NotificationPublisher notificationPublisher;
    private ReservationFinalizationService service;

    @BeforeEach
    void setUp() {
        service = new ReservationFinalizationService(
                reservationRepository,
                sessionRepository,
                capacityService,
                bookabilityPolicy,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void latePaymentRequiresRefundWhenCapacityIsNoLongerAvailable() {
        UUID reservationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        when(reservationRepository.findById(reservationId)).thenReturn(Optional.of(reservation));
        when(reservation.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(sessionId);
        when(sessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));
        when(reservationRepository.findByIdForUpdate(reservationId)).thenReturn(Optional.of(reservation));
        when(reservation.getStatus()).thenReturn(ReservationStatus.PENDING_PAYMENT);
        when(reservation.isHoldExpired(NOW)).thenReturn(true);
        when(reservation.getParticipantCount()).thenReturn(2);
        when(reservation.getTourist()).thenReturn(org.mockito.Mockito.mock(User.class));
        when(bookabilityPolicy.isBookable(session, NOW)).thenReturn(true);
        when(capacityService.availableCapacity(session, 0)).thenReturn(1);

        ReservationFinalizationResult result = service.finalizeAfterPaymentVerification(reservationId);

        assertThat(result.refundRequired()).isTrue();
        verify(reservation).expire();
        verify(reservation, never()).confirmAfterVerifiedPayment();
        verify(notificationPublisher, never()).publish(org.mockito.ArgumentMatchers.any());
    }
}
