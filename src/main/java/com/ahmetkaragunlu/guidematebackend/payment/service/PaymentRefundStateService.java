package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderRefundResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentRefundStateService {

    private final RefundRepository refundRepository;
    private final PaymentProperties properties;
    private final ProviderFailureCodeMapper failureCodeMapper;
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
        } else {
            refund.fail(failureCodeMapper.toStableCode(result.providerFailureCode()));
        }
    }

    @Transactional
    public void markUncertain(UUID refundId) {
        refundRepository.findByIdForUpdate(refundId)
                .ifPresent(refund -> refund.requireManualReview("PROVIDER_RESULT_UNCERTAIN"));
    }
}
