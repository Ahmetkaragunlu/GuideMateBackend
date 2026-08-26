package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PaymentRecoverySchedulerTest {

    private static final Instant NOW = Instant.parse("2026-08-27T10:00:00Z");

    private PaymentRepository paymentRepository;
    private PaymentReconciliationStateService stateService;
    private PaymentReconciliationService reconciliationService;
    private SchedulerProperties properties;
    private PaymentRecoveryScheduler scheduler;

    @BeforeEach
    void setUp() {
        paymentRepository = mock(PaymentRepository.class);
        stateService = mock(PaymentReconciliationStateService.class);
        reconciliationService = mock(PaymentReconciliationService.class);
        properties = TestSchedulerProperties.defaults();
        scheduler = new PaymentRecoveryScheduler(
                paymentRepository,
                stateService,
                reconciliationService,
                properties,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void reconcilesClaimedCandidatesAndIsolatesProviderFailure() {
        UUID successful = UUID.randomUUID();
        UUID alreadyClaimed = UUID.randomUUID();
        UUID failed = UUID.randomUUID();
        when(paymentRepository.findReconciliationCandidateIds(
                PaymentMethod.HOSTED_CARD,
                List.of(PaymentStatus.REQUIRES_ACTION, PaymentStatus.VERIFYING, PaymentStatus.TIMEOUT),
                NOW,
                NOW.minus(properties.paymentRetryDelay()),
                properties.paymentMaxAttempts(),
                PageRequest.of(0, properties.batchSize())
        )).thenReturn(List.of(successful, alreadyClaimed, failed));
        when(stateService.begin(successful)).thenReturn(true);
        when(stateService.begin(alreadyClaimed)).thenReturn(false);
        when(stateService.begin(failed)).thenReturn(true);
        doThrow(new IllegalStateException("provider unavailable"))
                .when(reconciliationService)
                .reconcile(failed);

        scheduler.reconcileUncertainPayments();

        verify(reconciliationService).reconcile(successful);
        verify(reconciliationService, never()).reconcile(alreadyClaimed);
        verify(reconciliationService).reconcile(failed);
        verify(stateService).markUncertain(failed);
    }
}
