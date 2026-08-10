package com.ahmetkaragunlu.guidematebackend.reservation.domain;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ReservationStateTest {

    @Test
    void confirmedLatePaymentRestoresActiveReservationGuard() {
        Reservation reservation = Reservation.hold(
                mock(TourSession.class),
                new User(),
                1,
                1000,
                1000,
                "USD",
                Instant.parse("2026-08-10T00:15:00Z"),
                "FULL_REFUND_48_HOURS",
                1,
                1,
                "{}",
                "booking-key"
        );

        reservation.expire();
        reservation.confirmAfterVerifiedPayment();

        assertThat(reservation.getStatus()).isEqualTo(ReservationStatus.CONFIRMED);
        assertThat(reservation.getActiveGuard()).isTrue();
        assertThat(reservation.getHoldExpiresAt()).isNull();
    }
}
