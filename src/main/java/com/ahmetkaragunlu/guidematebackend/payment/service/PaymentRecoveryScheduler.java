package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class PaymentRecoveryScheduler {

    private static final List<PaymentStatus> RECONCILABLE_STATUSES = List.of(
            PaymentStatus.REQUIRES_ACTION,
            PaymentStatus.VERIFYING,
            PaymentStatus.TIMEOUT
    );

    private final PaymentRepository paymentRepository;
    private final PaymentReconciliationStateService stateService;
    private final PaymentReconciliationService reconciliationService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.payment-delay-ms:60000}",
            fixedDelayString = "${scheduler.payment-delay-ms:60000}"
    )
    public void reconcileUncertainPayments() {
        Instant now = clock.instant();
        paymentRepository.findReconciliationCandidateIds(
                PaymentMethod.HOSTED_CARD,
                RECONCILABLE_STATUSES,
                now,
                now.minus(properties.paymentRetryDelay()),
                properties.paymentMaxAttempts(),
                PageRequest.of(0, properties.batchSize())
        ).forEach(this::reconcileSafely);
    }

    private void reconcileSafely(UUID paymentId) {
        if (!stateService.begin(paymentId)) {
            return;
        }
        try {
            reconciliationService.reconcile(paymentId);
        } catch (RuntimeException exception) {
            stateService.markUncertain(paymentId);
            log.warn("Payment reconciliation will retry payment {}", paymentId);
        }
    }
}
