package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CancellationPolicyTest {

    private static final Instant CANCELLED_AT = Instant.parse("2026-08-27T10:00:00Z");

    private final CancellationPolicy policy = new CancellationPolicy();

    @Test
    void grantsFullRefundAtExactFortyEightHourBoundary() {
        Reservation reservation = confirmedReservation(CANCELLED_AT.plusSeconds(48 * 60 * 60));

        assertThat(policy.touristEligibility(reservation, CANCELLED_AT))
                .isEqualTo(RefundEligibility.FULL_REFUND);
    }

    @Test
    void deniesRefundInsideFortyEightHourWindow() {
        Reservation reservation = confirmedReservation(CANCELLED_AT.plusSeconds(48 * 60 * 60 - 1));

        assertThat(policy.touristEligibility(reservation, CANCELLED_AT))
                .isEqualTo(RefundEligibility.NO_REFUND);
    }

    @Test
    void pendingPaymentCancellationDoesNotCreateRefundEligibility() {
        Reservation reservation = mock(Reservation.class);
        when(reservation.getStatus()).thenReturn(ReservationStatus.PENDING_PAYMENT);

        assertThat(policy.touristEligibility(reservation, CANCELLED_AT))
                .isEqualTo(RefundEligibility.NOT_APPLICABLE);
    }

    @Test
    void rejectsUnknownPolicySnapshot() {
        Reservation reservation = confirmedReservation(CANCELLED_AT.plusSeconds(72 * 60 * 60));
        when(reservation.getCancellationPolicyVersion()).thenReturn(2);

        assertThatThrownBy(() -> policy.touristEligibility(reservation, CANCELLED_AT))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.DATA_CONFLICT));
    }

    @Test
    void operatorCancellationRefundsOnlyConfirmedReservation() {
        Reservation confirmed = mock(Reservation.class);
        when(confirmed.getStatus()).thenReturn(ReservationStatus.CONFIRMED);
        Reservation completed = mock(Reservation.class);
        when(completed.getStatus()).thenReturn(ReservationStatus.COMPLETED);

        assertThat(policy.operatorEligibility(confirmed)).isEqualTo(RefundEligibility.FULL_REFUND);
        assertThat(policy.operatorEligibility(completed)).isEqualTo(RefundEligibility.NOT_APPLICABLE);
    }

    private Reservation confirmedReservation(Instant startsAt) {
        TourSession session = mock(TourSession.class);
        when(session.getStartsAt()).thenReturn(startsAt);
        Reservation reservation = mock(Reservation.class);
        when(reservation.getStatus()).thenReturn(ReservationStatus.CONFIRMED);
        when(reservation.getCancellationPolicyCode()).thenReturn(policy.currentCode());
        when(reservation.getCancellationPolicyVersion()).thenReturn(policy.currentVersion());
        when(reservation.getSession()).thenReturn(session);
        return reservation;
    }
}
