package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class RefundNotificationPublisher {

    private final NotificationPublisher notificationPublisher;

    public void publish(Refund refund, NotificationType type) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("refundId", refund.getId().toString());
        payload.put("paymentId", refund.getPayment().getId().toString());
        payload.put("amountMinor", refund.getAmountMinor());
        payload.put("currencyCode", refund.getCurrencyCode());
        payload.put("chargeAmountMinor", refund.getChargeAmountMinor());
        payload.put("chargeCurrencyCode", refund.getChargeCurrencyCode());
        if (refund.getPayment().getReservation() != null) {
            payload.put("reservationId", refund.getPayment().getReservation().getId().toString());
            payload.put(
                    "tourId",
                    refund.getPayment().getReservation().getSession().getTour().getId().toString()
            );
        }
        notificationPublisher.publish(new NotificationCommand(
                refund.getPayment().getUser().getId(),
                type,
                null,
                payload
        ));
    }
}
