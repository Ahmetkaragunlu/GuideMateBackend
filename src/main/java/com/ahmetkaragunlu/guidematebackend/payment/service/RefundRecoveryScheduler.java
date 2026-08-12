package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
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
public class RefundRecoveryScheduler {

    private static final List<RefundStatus> RETRYABLE_STATUSES = List.of(
            RefundStatus.REQUESTED,
            RefundStatus.FAILED
    );

    private final RefundRepository refundRepository;
    private final PaymentRefundProcessor refundProcessor;
    private final PaymentRefundStateService stateService;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Scheduled(
            initialDelayString = "${scheduler.refund-delay-ms:60000}",
            fixedDelayString = "${scheduler.refund-delay-ms:60000}"
    )
    public void recoverRefunds() {
        Instant now = clock.instant();
        refundRepository.findRetryCandidateIds(
                RETRYABLE_STATUSES,
                now.minus(properties.refundRetryDelay()),
                properties.refundMaxAttempts(),
                PageRequest.of(0, properties.batchSize())
        ).forEach(this::retrySafely);

        refundRepository.findStaleProcessingIds(
                RefundStatus.PROCESSING,
                now.minus(properties.refundProcessingTimeout()),
                PageRequest.of(0, properties.batchSize())
        ).forEach(stateService::markUncertain);
    }

    private void retrySafely(UUID refundId) {
        try {
            refundProcessor.process(new RefundRequestedEvent(refundId));
        } catch (RuntimeException exception) {
            log.warn("Refund recovery will retry refund {}", refundId);
        }
    }
}
