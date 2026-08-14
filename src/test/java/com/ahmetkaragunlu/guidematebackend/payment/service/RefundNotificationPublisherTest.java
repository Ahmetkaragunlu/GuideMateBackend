package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefundNotificationPublisherTest {

    @Mock
    private NotificationPublisher notificationPublisher;

    @Test
    void publishesCanonicalRefundNavigationPayload() {
        UUID refundId = UUID.randomUUID();
        UUID paymentId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        Refund refund = mock(Refund.class);
        Payment payment = mock(Payment.class);
        Reservation reservation = mock(Reservation.class);
        TourSession session = mock(TourSession.class);
        Tour tour = mock(Tour.class);
        User user = mock(User.class);
        when(refund.getId()).thenReturn(refundId);
        when(refund.getPayment()).thenReturn(payment);
        when(refund.getAmountMinor()).thenReturn(1_000L);
        when(refund.getCurrencyCode()).thenReturn("USD");
        when(refund.getChargeAmountMinor()).thenReturn(900L);
        when(refund.getChargeCurrencyCode()).thenReturn("EUR");
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getReservation()).thenReturn(reservation);
        when(payment.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(42L);
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getSession()).thenReturn(session);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);

        new RefundNotificationPublisher(notificationPublisher)
                .publish(refund, NotificationType.REFUND_COMPLETED);

        ArgumentCaptor<NotificationCommand> captor = ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(captor.capture());
        NotificationCommand command = captor.getValue();
        assertThat(command.recipientId()).isEqualTo(42L);
        assertThat(command.type()).isEqualTo(NotificationType.REFUND_COMPLETED);
        assertThat(command.payload()).containsEntry("refundId", refundId.toString());
        assertThat(command.payload()).containsEntry("paymentId", paymentId.toString());
        assertThat(command.payload()).containsEntry("reservationId", reservationId.toString());
        assertThat(command.payload()).containsEntry("tourId", tourId.toString());
        assertThat(command.payload()).containsEntry("amountMinor", 1_000L);
        assertThat(command.payload()).containsEntry("chargeAmountMinor", 900L);
    }
}
