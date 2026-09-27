package com.ahmetkaragunlu.guidematebackend.payment.service.payment.processing;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class PaymentNotificationPublisher {

    private final NotificationPublisher notificationPublisher;

    public void publish(Payment payment, NotificationType type) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("paymentId", payment.getId().toString());
        payload.put("purpose", payment.getPurpose().name());
        payload.put("amountMinor", payment.getAmountMinor());
        payload.put("currencyCode", payment.getCurrencyCode());
        if (payment.getReservation() != null) {
            payload.put("reservationId", payment.getReservation().getId().toString());
            payload.put("tourId", payment.getReservation().getSession().getTour().getId().toString());
        }
        notificationPublisher.publish(new NotificationCommand(
                payment.getUser().getId(),
                type,
                null,
                payload,
                "payment:" + payment.getId()
        ));
    }
}
