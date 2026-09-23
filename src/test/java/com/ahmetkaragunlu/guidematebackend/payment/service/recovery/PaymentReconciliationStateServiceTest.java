package com.ahmetkaragunlu.guidematebackend.payment.service.recovery;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.support.TestSchedulerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentReconciliationStateServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @Mock private PaymentRepository paymentRepository;
    private PaymentReconciliationStateService service;

    @BeforeEach
    void setUp() {
        service = new PaymentReconciliationStateService(
                paymentRepository,
                TestSchedulerProperties.defaults(),
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void startsExpiredPaymentWithinRetryBudget() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = eligiblePayment();
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));

        assertThat(service.begin(paymentId)).isTrue();
        verify(payment).markReconciliationAttempt(NOW);
    }

    @Test
    void skipsRecentlyAttemptedPayment() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = eligiblePayment();
        when(payment.getLastReconciliationAt()).thenReturn(NOW.minusSeconds(30));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));

        assertThat(service.begin(paymentId)).isFalse();
        verify(payment, never()).markReconciliationAttempt(NOW);
    }

    @Test
    void marksOnlyExistingPaymentUncertain() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));

        service.markUncertain(paymentId);

        verify(payment).markReconciliationUncertain();
    }

    private Payment eligiblePayment() {
        Payment payment = mock(Payment.class);
        when(payment.getStatus()).thenReturn(PaymentStatus.REQUIRES_ACTION);
        when(payment.getExpiresAt()).thenReturn(NOW.minusSeconds(1));
        when(payment.getReconciliationAttemptCount()).thenReturn(0);
        return payment;
    }
}
