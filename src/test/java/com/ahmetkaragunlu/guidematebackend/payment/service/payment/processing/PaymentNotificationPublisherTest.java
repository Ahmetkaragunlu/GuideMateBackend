package com.ahmetkaragunlu.guidematebackend.payment.service.payment.processing;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
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
class PaymentNotificationPublisherTest {

    @Mock
    private NotificationPublisher notificationPublisher;

    @Test
    void publishesCanonicalPaymentNavigationPayload() {
        UUID paymentId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        Reservation reservation = mock(Reservation.class);
        TourSession session = mock(TourSession.class);
        Tour tour = mock(Tour.class);
        User user = mock(User.class);
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getPurpose()).thenReturn(PaymentPurpose.TOUR_BOOKING);
        when(payment.getAmountMinor()).thenReturn(10_000L);
        when(payment.getCurrencyCode()).thenReturn("USD");
        when(payment.getReservation()).thenReturn(reservation);
        when(payment.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(42L);
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getSession()).thenReturn(session);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);

        new PaymentNotificationPublisher(notificationPublisher)
                .publish(payment, NotificationType.PAYMENT_SUCCEEDED);

        ArgumentCaptor<NotificationCommand> captor = ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(captor.capture());
        NotificationCommand command = captor.getValue();
        assertThat(command.recipientId()).isEqualTo(42L);
        assertThat(command.type()).isEqualTo(NotificationType.PAYMENT_SUCCEEDED);
        assertThat(command.deduplicationKey()).isEqualTo("payment:" + paymentId);
        assertThat(command.payload()).containsEntry("paymentId", paymentId.toString());
        assertThat(command.payload()).containsEntry("reservationId", reservationId.toString());
        assertThat(command.payload()).containsEntry("tourId", tourId.toString());
        assertThat(command.payload()).containsEntry("amountMinor", 10_000L);
    }
}
