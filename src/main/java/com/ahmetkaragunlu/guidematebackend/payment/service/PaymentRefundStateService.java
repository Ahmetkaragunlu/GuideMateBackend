package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderRefundResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentRefundStateService {

    private final RefundRepository refundRepository;
    private final PaymentProperties properties;
    private final ProviderFailureCodeMapper failureCodeMapper;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

    @Transactional
    public RefundProcessingCommand begin(UUID refundId) {
        Refund refund = refundRepository.findByIdForUpdate(refundId).orElse(null);
        if (refund == null
                || (refund.getStatus() != RefundStatus.REQUESTED
                && refund.getStatus() != RefundStatus.FAILED)) {
            return null;
        }
        refund.markProcessing();
        return new RefundProcessingCommand(
                refund.getId(),
                "guidemate-refund-" + refund.getId(),
                refund.getPayment().getProviderTransactionId(),
                refund.getAmountMinor(),
                refund.getCurrencyCode(),
                properties.sandboxBuyer().ipAddress()
        );
    }

    @Transactional
    public void complete(UUID refundId, ProviderRefundResult result) {
        Refund refund = refundRepository.findByIdForUpdate(refundId).orElse(null);
        if (refund == null || refund.getStatus() == RefundStatus.SUCCEEDED) {
            return;
        }
        if (result.successful()) {
            refund.succeed(result.providerRefundId(), clock.instant());
            publishRefund(refund, NotificationType.REFUND_COMPLETED);
        } else {
            refund.fail(failureCodeMapper.toStableCode(result.providerFailureCode()));
            publishRefund(refund, NotificationType.REFUND_FAILED);
        }
    }

    @Transactional
    public void markUncertain(UUID refundId) {
        refundRepository.findByIdForUpdate(refundId).ifPresent(refund -> {
            if (refund.getStatus() == RefundStatus.SUCCEEDED
                    || refund.getStatus() == RefundStatus.MANUAL_REVIEW) {
                return;
            }
            refund.requireManualReview("PROVIDER_RESULT_UNCERTAIN");
            publishRefund(refund, NotificationType.REFUND_MANUAL_REVIEW);
        });
    }

    private void publishRefund(Refund refund, NotificationType type) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("refundId", refund.getId().toString());
        payload.put("paymentId", refund.getPayment().getId().toString());
        payload.put("amountMinor", refund.getAmountMinor());
        payload.put("currencyCode", refund.getCurrencyCode());
        if (refund.getPayment().getReservation() != null) {
            payload.put("reservationId", refund.getPayment().getReservation().getId().toString());
        }
        notificationPublisher.publish(new NotificationCommand(
                refund.getPayment().getUser().getId(),
                type,
                null,
                payload
        ));
    }
}
