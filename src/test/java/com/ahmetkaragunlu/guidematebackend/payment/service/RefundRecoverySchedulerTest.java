package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RefundRecoverySchedulerTest {

    @Test
    void isolatesRetryFailureAndMarksStaleProcessingRefund() {
        Instant now = Instant.parse("2026-08-27T10:00:00Z");
        SchedulerProperties properties = TestSchedulerProperties.defaults();
        RefundRepository repository = mock(RefundRepository.class);
        PaymentRefundProcessor processor = mock(PaymentRefundProcessor.class);
        PaymentRefundStateService stateService = mock(PaymentRefundStateService.class);
        RefundRecoveryScheduler scheduler = new RefundRecoveryScheduler(
                repository,
                processor,
                stateService,
                properties,
                Clock.fixed(now, ZoneOffset.UTC)
        );
        UUID failed = UUID.randomUUID();
        UUID successful = UUID.randomUUID();
        UUID stale = UUID.randomUUID();
        when(repository.findRetryCandidateIds(
                List.of(RefundStatus.REQUESTED, RefundStatus.FAILED),
                now.minus(properties.refundRetryDelay()),
                properties.refundMaxAttempts(),
                PageRequest.of(0, properties.batchSize())
        )).thenReturn(List.of(failed, successful));
        when(repository.findStaleProcessingIds(
                RefundStatus.PROCESSING,
                now.minus(properties.refundProcessingTimeout()),
                PageRequest.of(0, properties.batchSize())
        )).thenReturn(List.of(stale));
        doThrow(new IllegalStateException("refund unavailable"))
                .when(processor)
                .process(new RefundRequestedEvent(failed));

        scheduler.recoverRefunds();

        verify(processor).process(new RefundRequestedEvent(failed));
        verify(processor).process(new RefundRequestedEvent(successful));
        verify(stateService).markUncertain(stale);
    }
}
