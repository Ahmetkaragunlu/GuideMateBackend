package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationTimeoutStateServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @Mock private ReservationBookingService bookingService;
    @Mock private ReservationRepository reservationRepository;
    @Mock private PaymentRepository paymentRepository;
    private ReservationTimeoutStateService service;

    @BeforeEach
    void setUp() {
        service = new ReservationTimeoutStateService(
                bookingService,
                reservationRepository,
                paymentRepository,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void expiresHoldAndEveryNonTerminalPaymentUnderSameSessionLock() {
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        Payment first = org.mockito.Mockito.mock(Payment.class);
        Payment second = org.mockito.Mockito.mock(Payment.class);
        when(reservationRepository.findByIdForUpdate(reservationId)).thenReturn(Optional.of(reservation));
        when(reservation.getStatus()).thenReturn(ReservationStatus.PENDING_PAYMENT);
        when(reservation.isHoldExpired(NOW)).thenReturn(true);
        when(paymentRepository.findByReservationIdAndStatusesForUpdate(
                org.mockito.ArgumentMatchers.eq(reservationId),
                anyList()
        )).thenReturn(List.of(first, second));

        service.expireHold(reservationId);

        verify(bookingService).lockSessionForReservation(reservationId);
        verify(first).timeout();
        verify(second).timeout();
        verify(reservation).expire();
    }
}
